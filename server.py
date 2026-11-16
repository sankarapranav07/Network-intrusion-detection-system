import argparse
import csv
import inspect
import math
import os
import selectors
import socket
import subprocess
import time
from collections import deque
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from host_firewall import (
    BLOCK_LOG, CONTROL_PATH, HOST, PORT, handle_block_request, install_firewall, list_host_blocks,
)
from ids_engine import ConfigError, IDSConfig

HOST_TIMING_COLUMNS = (
    "event_utc", "event", "source_ip", "destination_ip", "syn_threshold", "window_seconds",
    "detection_ms", "response_confirmation_ms", "end_to_end_ms",
)
HOST_BLOCK_POLL_SECONDS = 0.2


def incoming_syn_source(packet, address):
    """Read only the headers needed to match the firewall's IPv4 SYN rule."""
    if address[2] != 0 or len(packet) < 20 or packet[0] >> 4 != 4 or packet[9] != socket.IPPROTO_TCP:
        return None
    header_size = (packet[0] & 0x0F) * 4
    if header_size < 20 or len(packet) < header_size + 20:
        return None
    if packet[16:20] != socket.inet_aton(HOST) or int.from_bytes(packet[6:8], "big") & 0x1FFF:
        return None
    if (packet[header_size + 13] & 0x17) != 0x02:  # SYN set, ACK/RST/FIN clear.
        return None
    return socket.inet_ntoa(packet[12:16])


def publish_block_message(message):
    print(message, flush=True)
    try:
        with BLOCK_LOG.open("a", encoding="utf-8") as events:
            print(message, file=events)
    except OSError as exc:
        print(f"[-] Could not publish block notification: {exc}", flush=True)


@dataclass
class HostTiming:
    """Time h1's SYN-rate threshold and its first observation of an active block."""

    path: Path
    window: int
    threshold: int
    whitelist: set
    syns: dict = field(default_factory=dict)
    pending: dict = field(default_factory=dict)

    @classmethod
    def start(cls, config, path):
        timing = cls(path, math.ceil(config.window_seconds), config.attempts_threshold, set(config.whitelist))
        timing.write_rows(())
        return timing

    def write_rows(self, rows):
        try:
            with self.path.open("a", encoding="utf-8", newline="") as output:
                writer = csv.writer(output)
                if output.tell() == 0:
                    writer.writerow(HOST_TIMING_COLUMNS)
                writer.writerows(rows)
        except OSError as exc:
            print(f"[-] Host timing CSV: {exc}", flush=True)

    def observe(self, source, arrived, active):
        if source in self.whitelist or source in self.pending or source in active:
            return
        window = self.syns.setdefault(source, deque())
        while window and window[0] <= arrived - self.window:
            window.popleft()
        window.append(arrived)
        if len(window) == self.threshold:
            first = window[0]
            self.pending[source] = (first, arrived)
            del self.syns[source]
            self.record("DETECTED", source, first, arrived)

    def receive(self, capture, active):
        for _ in range(128):
            try:
                packet, address = capture.recvfrom(80)
            except BlockingIOError:
                break
            arrived = time.monotonic()
            source = incoming_syn_source(packet, address)
            if source is not None:
                self.observe(source, arrived, active)

    def observe_blocks(self, active, newly_blocked, observed):
        for source in sorted(newly_blocked):
            self.syns.pop(source, None)
            if source in self.pending:
                first, detected = self.pending.pop(source)
                self.record("BLOCK_CONFIRMED", source, first, detected, observed)
            else:
                self.record("BLOCK_OBSERVED", source, None, None, observed)
        self.syns = {source: stamps for source, stamps in self.syns.items()
                     if source not in active and stamps[-1] > observed - self.window}
        self.pending = {source: times for source, times in self.pending.items()
                        if times[1] > observed - self.window}

    def record(self, event, source, first, detected, confirmed=None):
        detection = (detected - first) * 1000 if first is not None else None
        have_response = confirmed is not None and detected is not None
        response = (confirmed - detected) * 1000 if have_response else None
        total = (confirmed - first) * 1000 if have_response else None
        self.write_rows([(
            datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            event, source, HOST, self.threshold, self.window,
            round(detection, 3) if detection is not None else None,
            round(response, 3) if response is not None else None,
            round(total, 3) if total is not None else None,
        )])
        if detection is None:
            message = f"[TIMING] {source} | block observed on h1 | threshold timing unavailable"
        else:
            message = f"[TIMING] {source} | detection {detection:.3f} ms"
            if response is not None:
                message += f" | h1 block confirmed in {response:.3f} ms | total {total:.3f} ms"
        publish_block_message(message)


@contextmanager
def block_listener(controller_uid):
    import fcntl

    CONTROL_PATH.parent.mkdir(mode=0o755, exist_ok=True)
    CONTROL_PATH.parent.chmod(0o755)
    with (CONTROL_PATH.parent / "server.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise OSError("another server owns the IDS control socket") from exc
        CONTROL_PATH.unlink(missing_ok=True)

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            previous_umask = os.umask(0o177)
            try:
                listener.bind(str(CONTROL_PATH))
            finally:
                os.umask(previous_umask)
            try:
                # The filesystem socket accepts connections from this UID and root.
                os.chown(CONTROL_PATH, controller_uid, 0)
                CONTROL_PATH.chmod(0o600)
                listener.listen(8)
                yield listener
            finally:
                CONTROL_PATH.unlink(missing_ok=True)


def start_server(controller_uid):
    directory = Path(inspect.getfile(start_server)).resolve().parent
    config = IDSConfig.from_file(directory / "rules.json")
    duration = math.ceil(config.block_duration_seconds)
    reported = set()
    next_check = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOST, PORT))

        with block_listener(controller_uid) as control, selectors.DefaultSelector() as ready, ExitStack() as resources:
            install_firewall(config)
            listener.listen(10)
            ready.register(control, selectors.EVENT_READ)
            ready.register(listener, selectors.EVENT_READ)
            BLOCK_LOG.touch(mode=0o644, exist_ok=True)
            capture = timing = None
            if config.rate_rule_enabled:
                try:
                    capture = resources.enter_context(
                        socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
                    )
                    capture.setblocking(False)
                    ready.register(capture, selectors.EVENT_READ)
                except OSError as exc:
                    print(f"[-] Host timing could not open IPv4 capture: {exc}", flush=True)
                else:
                    timing = HostTiming.start(config, directory / "h1_intrusion_timing.csv")
                    print(f"[TIMING] h1 CSV at {timing.path}", flush=True)
            print(f"[*] Server active on {HOST}:{PORT}; IDS controller UID {controller_uid}", flush=True)

            while True:
                for key, _ in ready.select(max(0, next_check - time.monotonic())):
                    if key.fileobj is capture:
                        timing.receive(capture, reported)
                        continue
                    connection, address = key.fileobj.accept()
                    with connection:
                        if key.fileobj is control:
                            try:
                                handle_block_request(connection)
                            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                                print(f"[-] Host block failed: {getattr(exc, 'stderr', None) or exc}", flush=True)
                        else:
                            try:
                                connection.settimeout(1.0)
                                connection.sendall(b"ACK: Received\n")
                                print(f"[+] Connection received from {address[0]}:{address[1]}", flush=True)
                            except OSError as exc:
                                print(f"[-] Reply to {address[0]} failed: {exc}", flush=True)

                if time.monotonic() >= next_check:
                    try:
                        active = list_host_blocks()
                        newly_blocked = active - reported
                        if timing is not None:
                            if newly_blocked:
                                # The threshold SYN can arrive while ipset is being sampled.
                                timing.receive(capture, reported)
                            timing.observe_blocks(active, newly_blocked, time.monotonic())
                        for address in sorted(newly_blocked):
                            source = f"h3 ({address})" if address == "10.0.0.3" else address
                            message = f"[BLOCKED] {source} has been blocked from h1 for {duration} seconds"
                            publish_block_message(message)
                        reported = active
                    except (OSError, subprocess.SubprocessError) as exc:
                        print(f"[-] Could not publish block notifications: {exc}", flush=True)
                    next_check = time.monotonic() + HOST_BLOCK_POLL_SECONDS


def main():
    parser = argparse.ArgumentParser(description="Run the Mininet server with host firewall enforcement.")
    parser.add_argument("--controller-uid", type=int, default=os.environ.get("SUDO_UID", "0"))
    args = parser.parse_args()
    if not 0 <= args.controller_uid < 2**32 - 1:
        parser.error("--controller-uid must be a valid Linux UID")
    try:
        start_server(args.controller_uid)
    except KeyboardInterrupt:
        pass
    except (ConfigError, OSError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"Server failed: {getattr(exc, 'stderr', None) or exc}\n")


# Keep the script entry point intact even if a transfer collapses double underscores.
marker = chr(95) * 2
if globals().get(f"{marker}name{marker}") == f"{marker}main{marker}":
    main()

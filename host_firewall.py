"""Local control channel and timed IPv4 blocks for the Mininet server."""

import ipaddress
import math
import socket
import struct
import subprocess
from pathlib import Path

HOST = "10.0.0.1"
PORT = 8080
CONTROL_PATH = Path("/run/cn-project-ids/block.sock")
BLOCK_LOG = CONTROL_PATH.with_name("blocks.log")
BLOCK_SET = "cn_project_ids"
INPUT_CHAIN = "CN_PROJECT_IDS"
RECENT_LIST = "cn_project_syn"
MAX_BLOCK_SECONDS = 65535

_REQUEST = struct.Struct("!4sH")
_OK = b"\x01"
_FAILED = b"\x00"


def request_host_block(src_ip, timeout_seconds, control_path=CONTROL_PATH):
    """Return once h1 has acknowledged the firewall entry, or raise."""
    address = ipaddress.IPv4Address(src_ip)
    if not 1 <= timeout_seconds <= MAX_BLOCK_SECONDS:
        raise ValueError("block timeout must be between 1 and 65535 seconds")

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
        control.settimeout(6.0)
        control.connect(str(control_path))
        control.sendall(_REQUEST.pack(address.packed, timeout_seconds))
        if control.recv(1) != _OK:
            raise OSError("h1 did not acknowledge the firewall block")


def _run(*command, input=None):
    return subprocess.run(command, input=input, check=True, capture_output=True, text=True, timeout=2)


def install_firewall(config):
    """Enforce the SYN rate threshold in h1's kernel, before TCP sees the packet."""
    _run("ipset", "-exist", "create", BLOCK_SET, "hash:ip", "family", "inet", "timeout", "60")
    jump = ("-d", HOST, "-j", INPUT_CHAIN)
    drop = f"-A {INPUT_CHAIN} -m set --match-set {BLOCK_SET} src -j DROP"
    rules = ["*filter", f":{INPUT_CHAIN} - [0:0]", drop]
    if config.rate_rule_enabled:
        for address in config.whitelist:
            if ipaddress.ip_address(address).version == 4:
                rules.append(f"-A {INPUT_CHAIN} -s {address} -j RETURN")
        syn = f"-A {INPUT_CHAIN} -p tcp --syn -m recent --name {RECENT_LIST}"
        rules.extend([
            f"{syn} --set",
            f"{syn} --rcheck --seconds {math.ceil(config.window_seconds)} "
            f"--hitcount {config.attempts_threshold} -j SET --add-set {BLOCK_SET} src "
            f"--timeout {math.ceil(config.block_duration_seconds)}",
            drop,
        ])
    try:
        _run("iptables", "-w", "1", "-C", "INPUT", *jump)
    except subprocess.CalledProcessError:
        rules.append(f"-I INPUT 1 {' '.join(jump)}")
    _run("iptables-restore", "--wait", "1", "--noflush", input="\n".join([*rules, "COMMIT", ""]))


def list_host_blocks():
    """Read the active set for display, independently of controller requests."""
    output = _run("ipset", "save", BLOCK_SET).stdout
    return {line.split()[2] for line in output.splitlines() if line.startswith(f"add {BLOCK_SET} ")}


def handle_block_request(control):
    """Process one authenticated local request and acknowledge kernel membership."""
    control.settimeout(1.0)
    with control.makefile("rb") as request:
        frame = request.read(_REQUEST.size)
    if len(frame) != _REQUEST.size:
        control.sendall(_FAILED)
        raise ValueError("incomplete firewall request")

    packed_address, seconds = _REQUEST.unpack(frame)
    address = str(ipaddress.IPv4Address(packed_address))
    if seconds == 0:
        control.sendall(_FAILED)
        raise ValueError("a block must expire")

    try:
        try:
            _run("ipset", "add", BLOCK_SET, address, "timeout", str(seconds))
        except subprocess.CalledProcessError:
            # A kernel-triggered entry may already exist. Preserve its expiry.
            pass
        _run("ipset", "test", BLOCK_SET, address)
    except (OSError, subprocess.SubprocessError):
        control.sendall(_FAILED)
        raise
    control.sendall(_OK)
    return address, seconds

#!/usr/bin/env python3
"""
ids_engine.py - Rule-based, threshold-driven experimental TCP IDS (Member 3).

SCOPE
    Consumes *TCP connection-attempt observations* (one event per observed SYN)
    and maintains per-source rolling-window statistics. Emits alerts and,
    optionally, asks a Blocker to block the source.

    This module knows NOTHING about Ryu, Mininet, Open vSwitch or packet
    capture. Those are the job of traffic_monitor.py / the SDN controller.

IT IS NOT
    A proof of malicious intent. A source that crosses a threshold is only
    *flagged by a rule*. Thresholds are experimental and must be validated.

EVENT CONTRACT (PROPOSAL - confirm with teammates before treating as real)
    dict with:
      required : src_ip (str), dst_port (int 1..65535), ts (float >= 0)
      optional : dst_ip (str), src_port (int 0..65535), tcp_flags (str),
                 source (str, e.g. "synthetic" | "packet_in" | "pcap")
    ts is seconds from ONE shared monotonic clock (time.monotonic() on Linux is
    CLOCK_MONOTONIC and is comparable between processes on the same kernel -
    engineering note, not verified here). The engine uses event ts as its clock.
    tcp_flags, if present, must be a pure SYN ("S"/"SYN", case-insensitive);
    SYN-ACK/ACK/etc. are ignored (not counted, not malformed). If absent, the
    event is ASSUMED to be a connection attempt (the monitor's responsibility).

WINDOW SEMANTICS
    An observation at time t0 counts toward time t iff  t - W < t0 <= t
    (half-open). Alerts fire when a count is >= its threshold.

RETRANSMITTED SYNs
    If src_port is provided, repeats of the same (src_port, dst_ip, dst_port)
    within retransmit_window_seconds are counted once. Limitation: a flood that
    deliberately reuses one 4-tuple is under-counted. Without src_port no
    de-duplication is possible.

ALERT vs BLOCK
    An Alert is a detection. block_status says what happened to the block
    request. Only a real Blocker may return CONFIRMED, and only after verifying
    the rule. MockBlocker NEVER returns CONFIRMED.
"""
from __future__ import annotations

import bisect
import ipaddress
import json
import logging
import math
import time
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger("ids")


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
class ConfigError(ValueError):
    """Invalid or unreadable IDS configuration."""


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _canon_ip(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("IP must be a string")
    return str(ipaddress.ip_address(value.strip()))


@dataclass(frozen=True)
class IDSConfig:
    # --- all numeric values below are EXPERIMENTAL defaults ---
    window_seconds: float = 10.0
    rate_rule_enabled: bool = True
    attempts_threshold: int = 30
    port_rule_enabled: bool = True
    distinct_ports_threshold: int = 10
    retransmit_dedup_enabled: bool = True
    retransmit_window_seconds: float = 3.0
    block_duration_seconds: float = 60.0
    idle_state_ttl_seconds: float = 60.0
    block_retry_cooldown_seconds: float = 5.0
    block_max_retries: int = 2
    whitelist: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        def need(cond: bool, msg: str) -> None:
            if not cond:
                raise ConfigError(msg)

        need(_is_num(self.window_seconds) and self.window_seconds > 0,
             "window_seconds must be a number > 0")
        need(_is_int(self.attempts_threshold) and self.attempts_threshold >= 1,
             "attempts_threshold must be an integer >= 1")
        need(_is_int(self.distinct_ports_threshold) and self.distinct_ports_threshold >= 1,
             "distinct_ports_threshold must be an integer >= 1")
        need(_is_num(self.retransmit_window_seconds) and self.retransmit_window_seconds > 0,
             "retransmit window_seconds must be a number > 0")
        need(self.retransmit_window_seconds <= self.window_seconds,
             "retransmit window_seconds must be <= window_seconds")
        need(_is_num(self.block_duration_seconds) and self.block_duration_seconds > 0,
             "block_duration_seconds must be a number > 0")
        need(_is_num(self.idle_state_ttl_seconds) and self.idle_state_ttl_seconds >= 0,
             "idle_state_ttl_seconds must be a number >= 0")
        need(_is_num(self.block_retry_cooldown_seconds) and self.block_retry_cooldown_seconds >= 0,
             "block_retry_cooldown_seconds must be a number >= 0")
        need(_is_int(self.block_max_retries) and self.block_max_retries >= 0,
             "block_max_retries must be an integer >= 0")
        for flag in ("rate_rule_enabled", "port_rule_enabled", "retransmit_dedup_enabled"):
            need(isinstance(getattr(self, flag), bool), f"{flag} must be true/false")
        try:
            canon = tuple(_canon_ip(ip) for ip in self.whitelist)
        except ValueError as exc:
            raise ConfigError(f"whitelist contains an invalid IP: {exc}")
        object.__setattr__(self, "whitelist", canon)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "IDSConfig":
        if not isinstance(d, dict):
            raise ConfigError("config must be a JSON object")

        def check_keys(obj: Dict[str, Any], allowed: set, where: str) -> None:
            if not isinstance(obj, dict):
                raise ConfigError(f"'{where}' must be an object")
            unknown = [k for k in obj if not k.startswith("_") and k not in allowed]
            if unknown:
                raise ConfigError(f"unknown key(s) in {where}: {unknown}")

        check_keys(d, {"window_seconds", "rules", "retransmit_dedup", "incident", "whitelist"}, "top level")
        rules = d.get("rules", {})
        check_keys(rules, {"high_connection_rate", "multi_port_scan"}, "rules")
        rate = rules.get("high_connection_rate", {})
        check_keys(rate, {"enabled", "attempts_threshold"}, "rules.high_connection_rate")
        port = rules.get("multi_port_scan", {})
        check_keys(port, {"enabled", "distinct_ports_threshold"}, "rules.multi_port_scan")
        rt = d.get("retransmit_dedup", {})
        check_keys(rt, {"enabled", "window_seconds"}, "retransmit_dedup")
        inc = d.get("incident", {})
        check_keys(inc, {"block_duration_seconds", "idle_state_ttl_seconds",
                         "block_retry_cooldown_seconds", "block_max_retries"}, "incident")

        base = cls()
        wl = d.get("whitelist", [])
        if not isinstance(wl, list):
            raise ConfigError("whitelist must be a list")
        return cls(
            window_seconds=d.get("window_seconds", base.window_seconds),
            rate_rule_enabled=rate.get("enabled", base.rate_rule_enabled),
            attempts_threshold=rate.get("attempts_threshold", base.attempts_threshold),
            port_rule_enabled=port.get("enabled", base.port_rule_enabled),
            distinct_ports_threshold=port.get("distinct_ports_threshold", base.distinct_ports_threshold),
            retransmit_dedup_enabled=rt.get("enabled", base.retransmit_dedup_enabled),
            retransmit_window_seconds=rt.get("window_seconds", base.retransmit_window_seconds),
            block_duration_seconds=inc.get("block_duration_seconds", base.block_duration_seconds),
            idle_state_ttl_seconds=inc.get("idle_state_ttl_seconds", base.idle_state_ttl_seconds),
            block_retry_cooldown_seconds=inc.get("block_retry_cooldown_seconds",
                                                 base.block_retry_cooldown_seconds),
            block_max_retries=inc.get("block_max_retries", base.block_max_retries),
            whitelist=tuple(wl),
        )

    @classmethod
    def from_file(cls, path: str) -> "IDSConfig":
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"cannot read config '{path}': {exc}")
        return cls.from_dict(data)


# --------------------------------------------------------------------------- #
# Blocker interface (PROPOSED contract - confirm with the SDN teammate)
# --------------------------------------------------------------------------- #
class BlockStatus(str, Enum):
    NOT_REQUESTED = "NOT_REQUESTED"                # detection-only mode / no blocker
    MOCK_NOT_ENFORCED = "MOCK_NOT_ENFORCED"        # test double: NOTHING was blocked
    REQUESTED_UNVERIFIED = "REQUESTED_UNVERIFIED"  # real request sent, rule not verified
    CONFIRMED = "CONFIRMED"                        # real rule installed AND verified
    FAILED = "FAILED"                              # request failed / blocker error


@dataclass
class BlockResult:
    status: BlockStatus
    detail: str = ""


class Blocker(ABC):
    """Boundary between the IDS and the SDN controller."""

    @abstractmethod
    def block(self, src_ip: str, duration_seconds: float, reason: str) -> BlockResult:
        """Request a temporary block of src_ip.

        A real implementation should map duration_seconds to the OpenFlow
        hard_timeout, install a drop rule on the intended switch(es), verify it
        (e.g. flow-stats), and return CONFIRMED only if verified.
        """


class MockBlocker(Blocker):
    """TEST DOUBLE. Does NOT touch any switch. Never returns CONFIRMED."""

    def __init__(self, failures: int = 0, raise_on_call: bool = False) -> None:
        self.calls: List[Tuple[str, float, str]] = []
        self.failures_remaining = failures
        self.raise_on_call = raise_on_call

    def block(self, src_ip: str, duration_seconds: float, reason: str) -> BlockResult:
        self.calls.append((src_ip, duration_seconds, reason))
        log.warning("MOCK BLOCKER called for %s - NO real block installed", src_ip)
        if self.raise_on_call:
            raise RuntimeError("mock blocker configured to raise")
        if self.failures_remaining > 0:
            self.failures_remaining -= 1
            return BlockResult(BlockStatus.FAILED, "mock configured to fail")
        return BlockResult(BlockStatus.MOCK_NOT_ENFORCED, "mock: nothing was blocked")


# --------------------------------------------------------------------------- #
# Alerts and internal state
# --------------------------------------------------------------------------- #
@dataclass
class Alert:
    alert_id: int
    src_ip: str
    ts: float                    # event-clock time of the triggering observation
    first_event_ts: float        # earliest observation in the window at alert time
    rule: str                    # e.g. "high_connection_rate" or "a+b"
    reason: str
    observed_attempts: int
    observed_distinct_ports: int
    window_seconds: float
    data_source: str             # "synthetic", "packet_in", ... (from the event)
    emitted_mono: float          # time.monotonic() when the engine emitted the alert
    emitted_wall: float          # time.time() when the engine emitted the alert
    block_status: BlockStatus = BlockStatus.NOT_REQUESTED
    block_detail: str = ""
    block_request_mono: Optional[float] = None
    block_returned_mono: Optional[float] = None

    @property
    def is_confirmed_block(self) -> bool:
        return self.block_status == BlockStatus.CONFIRMED

    def to_dict(self) -> Dict[str, Any]:
        d = dict(self.__dict__)
        d["block_status"] = self.block_status.value
        return d


@dataclass
class _Incident:
    alert: Alert
    end_ts: float
    block_attempts: int = 0
    last_block_try_ts: Optional[float] = None


class _SourceState:
    __slots__ = ("window", "ports", "dst_ports", "key_last", "latest_ts", "last_seen", "incident")

    def __init__(self) -> None:
        self.window: List[Tuple[float, int, tuple, str]] = []   # sorted (ts, dst_port, key, dst_ip)
        self.ports: Counter = Counter()                  # dst_port -> count (all destinations)
        self.dst_ports: Dict[str, Counter] = {}          # dst_ip -> {dst_port -> count} (Rule 2)
        self.key_last: Dict[tuple, float] = {}
        self.latest_ts: Optional[float] = None
        self.last_seen: Optional[float] = None
        self.incident: Optional[_Incident] = None

    def reset_window(self) -> None:
        self.window.clear()
        self.ports.clear()
        self.dst_ports.clear()
        self.key_last.clear()
        self.latest_ts = None
        self.incident = None


class _Malformed(Exception):
    pass


class _Ignored(Exception):
    pass


@dataclass
class _Obs:
    src_ip: str
    dst_port: int
    ts: float
    dst_ip: str
    src_port: Optional[int]
    source: str


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #
class IDSEngine:
    def __init__(self,
                 config: Optional[IDSConfig] = None,
                 blocker: Optional[Blocker] = None,
                 on_alert: Optional[Callable[[Alert], None]] = None,
                 auto_block: bool = True) -> None:
        self.cfg = config or IDSConfig()
        self.blocker = blocker
        self.on_alert = on_alert
        self.auto_block = auto_block
        self._states: Dict[str, _SourceState] = {}
        self._next_alert_id = 1
        self.alerts: List[Alert] = []
        self.stats: Counter = Counter()

    # ----- public API ------------------------------------------------------ #
    def process_event(self, event: Any) -> Optional[Alert]:
        """Process one observation. Returns an Alert only when a NEW incident starts."""
        self.stats["events_received"] += 1
        try:
            obs = self._parse(event)
        except _Malformed as exc:
            self.stats["malformed"] += 1
            log.warning("event=malformed reason=%r", str(exc))
            return None
        except _Ignored:
            self.stats["ignored_non_syn"] += 1
            return None

        if obs.src_ip in self.cfg.whitelist:
            self.stats["whitelisted"] += 1
            return None

        st = self._states.get(obs.src_ip)
        if st is None:
            st = self._states[obs.src_ip] = _SourceState()

        # --- active incident handling (de-duplication) ---
        if st.incident is not None:
            if obs.ts >= st.incident.end_ts:
                self._end_incident(obs.src_ip, st, "block_duration_elapsed")
            else:
                self.stats["suppressed_during_incident"] += 1
                st.last_seen = max(st.last_seen or obs.ts, obs.ts)
                self._maybe_retry_block(obs.src_ip, st.incident, obs.ts)
                return None

        # --- stale / out-of-order guard ---
        w = self.cfg.window_seconds
        if st.latest_ts is not None and obs.ts < st.latest_ts - w:
            self.stats["stale_dropped"] += 1
            log.debug("event=stale src=%s ts=%s latest=%s", obs.src_ip, obs.ts, st.latest_ts)
            return None

        # --- retransmitted SYN de-duplication ---
        key: tuple = ()
        if obs.src_port is not None:
            key = (obs.src_port, obs.dst_ip, obs.dst_port)
            if self.cfg.retransmit_dedup_enabled:
                last = st.key_last.get(key)
                if last is not None and abs(obs.ts - last) < self.cfg.retransmit_window_seconds:
                    self.stats["retransmit_suppressed"] += 1
                    st.last_seen = max(st.last_seen or obs.ts, obs.ts)
                    return None

        # --- record the attempt ---
        bisect.insort(st.window, (obs.ts, obs.dst_port, key, obs.dst_ip))
        st.ports[obs.dst_port] += 1
        if obs.dst_ip:   # Rule 2 needs an identifiable destination server
            st.dst_ports.setdefault(obs.dst_ip, Counter())[obs.dst_port] += 1
        if key:
            st.key_last[key] = obs.ts
        st.latest_ts = obs.ts if st.latest_ts is None else max(st.latest_ts, obs.ts)
        st.last_seen = st.latest_ts
        self.stats["counted_attempts"] += 1
        self._prune(st)

        # --- evaluate rules ---
        attempts = len(st.window)
        distinct = len(st.ports)
        # Rule 2 is per destination server. Only the current event's destination can
        # newly cross the threshold (other destinations' counts only shrink via pruning).
        dst_distinct = len(st.dst_ports.get(obs.dst_ip, ())) if obs.dst_ip else 0
        fired: List[Tuple[str, str]] = []
        if self.cfg.rate_rule_enabled and attempts >= self.cfg.attempts_threshold:
            fired.append(("high_connection_rate",
                          f"{attempts} TCP connection attempts within {w:g}s "
                          f"(threshold {self.cfg.attempts_threshold})"))
        port_fired = (self.cfg.port_rule_enabled and obs.dst_ip != ""
                      and dst_distinct >= self.cfg.distinct_ports_threshold)
        if port_fired:
            fired.append(("multi_port_scan",
                          f"{dst_distinct} distinct destination ports within {w:g}s "
                          f"(threshold {self.cfg.distinct_ports_threshold}) "
                          f"against {obs.dst_ip}"))
            distinct = dst_distinct   # report the count that actually triggered the rule
        if not fired:
            return None
        return self._raise_alert(obs, st, fired, attempts, distinct)

    def expire(self, now: float) -> Dict[str, List[str]]:
        """Housekeeping. Call periodically with the same clock as event ts."""
        ended: List[str] = []
        purged: List[str] = []
        for ip, st in list(self._states.items()):
            if st.incident is not None and now >= st.incident.end_ts:
                self._end_incident(ip, st, "expired_by_timer")
                ended.append(ip)
            if st.incident is None and st.last_seen is not None:
                ttl = max(self.cfg.window_seconds, self.cfg.idle_state_ttl_seconds)
                if now - st.last_seen > ttl:
                    del self._states[ip]
                    purged.append(ip)
                    self.stats["states_purged"] += 1
        return {"incidents_ended": ended, "states_purged": purged}

    def is_incident_active(self, src_ip: str) -> bool:
        st = self._states.get(_canon_ip(src_ip))
        return bool(st and st.incident)

    def active_incidents(self) -> List[str]:
        return [ip for ip, st in self._states.items() if st.incident]

    # ----- internals ------------------------------------------------------- #
    def _parse(self, event: Any) -> _Obs:
        if not isinstance(event, dict):
            raise _Malformed("event is not a dict")
        missing = [k for k in ("src_ip", "dst_port", "ts") if event.get(k) is None]
        if missing:
            raise _Malformed(f"missing required field(s): {missing}")
        try:
            src_ip = _canon_ip(event["src_ip"])
        except ValueError as exc:
            raise _Malformed(f"invalid src_ip: {exc}")
        dst_ip = ""
        if event.get("dst_ip") is not None:
            try:
                dst_ip = _canon_ip(event["dst_ip"])
            except ValueError as exc:
                raise _Malformed(f"invalid dst_ip: {exc}")
        dp = event["dst_port"]
        if not _is_int(dp) or not 1 <= dp <= 65535:
            raise _Malformed("dst_port must be an int in 1..65535")
        ts = event["ts"]
        if not _is_num(ts) or ts < 0:
            raise _Malformed("ts must be a finite number >= 0")
        sp = event.get("src_port")
        if sp is not None and (not _is_int(sp) or not 0 <= sp <= 65535):
            raise _Malformed("src_port must be an int in 0..65535")
        flags = event.get("tcp_flags")
        if flags is not None:
            if not isinstance(flags, str):
                raise _Malformed("tcp_flags must be a string")
            if flags.strip().upper() not in ("S", "SYN"):
                raise _Ignored()
        return _Obs(src_ip, dp, float(ts), dst_ip, sp, str(event.get("source", "unknown")))

    def _prune(self, st: _SourceState) -> None:
        cutoff = st.latest_ts - self.cfg.window_seconds
        while st.window and st.window[0][0] <= cutoff:
            ts0, port0, key0, dst0 = st.window.pop(0)
            st.ports[port0] -= 1
            if st.ports[port0] <= 0:
                del st.ports[port0]
            if dst0:
                dc = st.dst_ports[dst0]
                dc[port0] -= 1
                if dc[port0] <= 0:
                    del dc[port0]
                if not dc:
                    del st.dst_ports[dst0]
            if key0 and st.key_last.get(key0) == ts0:
                del st.key_last[key0]

    def _raise_alert(self, obs: _Obs, st: _SourceState,
                     fired: List[Tuple[str, str]], attempts: int, distinct: int) -> Alert:
        alert = Alert(
            alert_id=self._next_alert_id,
            src_ip=obs.src_ip,
            ts=obs.ts,
            first_event_ts=st.window[0][0],
            rule="+".join(n for n, _ in fired),
            reason="; ".join(r for _, r in fired),
            observed_attempts=attempts,
            observed_distinct_ports=distinct,
            window_seconds=self.cfg.window_seconds,
            data_source=obs.source,
            emitted_mono=time.monotonic(),
            emitted_wall=time.time(),
        )
        self._next_alert_id += 1
        self.alerts.append(alert)
        self.stats["alerts"] += 1
        inc = _Incident(alert=alert, end_ts=obs.ts + self.cfg.block_duration_seconds)
        st.incident = inc
        log.warning("event=ALERT id=%d src=%s rule=%s reason=%r data_source=%s",
                    alert.alert_id, alert.src_ip, alert.rule, alert.reason, alert.data_source)

        if self.auto_block and self.blocker is not None:
            self._request_block(inc, obs.ts)
        else:
            log.info("event=block_skipped src=%s (detection-only or no blocker)", alert.src_ip)

        if self.on_alert is not None:
            try:
                self.on_alert(alert)
            except Exception:  # a faulty callback must not break detection
                log.exception("on_alert callback raised")
        return alert

    def _request_block(self, inc: _Incident, ts: float) -> None:
        alert = inc.alert
        t0 = time.monotonic()
        try:
            res = self.blocker.block(alert.src_ip, self.cfg.block_duration_seconds, alert.reason)
            if not isinstance(res, BlockResult) or not isinstance(res.status, BlockStatus):
                res = BlockResult(BlockStatus.FAILED, "blocker returned an invalid result")
        except Exception as exc:
            res = BlockResult(BlockStatus.FAILED, f"blocker raised {type(exc).__name__}: {exc}")
        t1 = time.monotonic()
        inc.block_attempts += 1
        inc.last_block_try_ts = ts
        alert.block_status = res.status
        alert.block_detail = res.detail
        alert.block_request_mono = t0
        alert.block_returned_mono = t1
        self.stats["block_requests"] += 1
        log.info("event=block_result src=%s status=%s detail=%r attempt=%d",
                 alert.src_ip, res.status.value, res.detail, inc.block_attempts)

    def _maybe_retry_block(self, src_ip: str, inc: _Incident, ts: float) -> None:
        if not (self.auto_block and self.blocker is not None):
            return
        if inc.alert.block_status != BlockStatus.FAILED:
            return
        if inc.block_attempts >= 1 + self.cfg.block_max_retries:
            return
        if inc.last_block_try_ts is not None and \
                ts - inc.last_block_try_ts < self.cfg.block_retry_cooldown_seconds:
            return
        log.info("event=block_retry src=%s", src_ip)
        self._request_block(inc, ts)

    def _end_incident(self, src_ip: str, st: _SourceState, why: str) -> None:
        log.info("event=incident_end src=%s why=%s", src_ip, why)
        self.stats["incidents_ended"] += 1
        st.reset_window()


# --------------------------------------------------------------------------- #
# Synthetic demo (NOT real network traffic)
# --------------------------------------------------------------------------- #
def _demo(config_path: Optional[str]) -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    cfg = IDSConfig.from_file(config_path) if config_path else IDSConfig()
    mock = MockBlocker()
    eng = IDSEngine(cfg, blocker=mock)
    print("=== SYNTHETIC DEMO: events are simulated, no real network, MockBlocker only ===")
    t = 0.0
    for i in range(5):                                   # legitimate-looking client
        eng.process_event({"src_ip": "10.0.0.1", "dst_ip": "10.0.0.9", "dst_port": 80,
                           "ts": t, "source": "synthetic"})
        t += 1.0
    for port in range(1, cfg.distinct_ports_threshold + 5):   # port scanner
        eng.process_event({"src_ip": "10.0.0.2", "dst_ip": "10.0.0.9", "dst_port": port,
                           "ts": t, "source": "synthetic"})
        t += 0.05
    print("alerts:", [a.to_dict() for a in eng.alerts])
    print("mock blocker calls:", mock.calls)
    print("stats:", dict(eng.stats))


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="IDS engine synthetic demo")
    ap.add_argument("--demo", action="store_true", help="run synthetic demo")
    ap.add_argument("--config", default=None, help="path to rules.json")
    args = ap.parse_args()
    if args.demo:
        _demo(args.config)
    else:
        ap.print_help()

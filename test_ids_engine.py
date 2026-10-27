#!/usr/bin/env python3
"""
Unit tests for ids_engine.py.

ALL events here are SYNTHETIC. These tests exercise detection logic only.
They say NOTHING about Ryu, Mininet, Open vSwitch, real SYN capture, or real
SDN blocking. Passing here = UNIT-TESTED, never "integration verified".

Run:  python3 -m unittest -v test_ids_engine
"""
import json
import os
import unittest

from ids_engine import (Alert, BlockResult, BlockStatus, Blocker, ConfigError,
                        IDSConfig, IDSEngine, MockBlocker)

HERE = os.path.dirname(os.path.abspath(__file__))
ATTACKER = "10.0.0.2"
LEGIT = "10.0.0.1"


def cfg(**kw):
    base = dict(window_seconds=10.0, attempts_threshold=5, distinct_ports_threshold=4,
                retransmit_window_seconds=2.0, block_duration_seconds=30.0,
                idle_state_ttl_seconds=20.0, block_retry_cooldown_seconds=3.0,
                block_max_retries=2)
    base.update(kw)
    return IDSConfig(**base)


def ev(src, port, ts, **kw):
    d = {"src_ip": src, "dst_port": port, "ts": ts, "source": "synthetic"}
    d.update(kw)
    return d


class TestRateRule(unittest.TestCase):
    def test_normal_traffic_below_threshold(self):
        e = IDSEngine(cfg())
        for i in range(4):
            self.assertIsNone(e.process_event(ev(LEGIT, 80, i)))
        self.assertEqual(len(e.alerts), 0)

    def test_rate_threshold_triggers_at_nth_event(self):
        e = IDSEngine(cfg())
        results = [e.process_event(ev(ATTACKER, 80, i * 0.1)) for i in range(5)]
        self.assertTrue(all(r is None for r in results[:4]))
        a = results[4]
        self.assertIsInstance(a, Alert)
        self.assertEqual(a.rule, "high_connection_rate")
        self.assertEqual(a.src_ip, ATTACKER)
        self.assertEqual(a.observed_attempts, 5)
        self.assertEqual(a.observed_distinct_ports, 1)
        self.assertEqual(a.data_source, "synthetic")
        self.assertIn("5 TCP connection attempts", a.reason)
        json.dumps(a.to_dict())  # must be serialisable for CSV/JSON logging

    def test_events_outside_window_do_not_accumulate(self):
        e = IDSEngine(cfg())
        for i in range(10):                      # one every 3 s -> max 4 in 10 s window
            self.assertIsNone(e.process_event(ev(LEGIT, 80, 3.0 * i)))
        self.assertEqual(len(e.alerts), 0)

    def test_window_is_half_open(self):
        e = IDSEngine(cfg())
        for t in (0, 2.5, 5, 7.5):
            e.process_event(ev(ATTACKER, 80, t))
        # at t=10 the t=0 observation is exactly W old -> excluded -> count stays 4
        self.assertIsNone(e.process_event(ev(ATTACKER, 80, 10)))
        a = e.process_event(ev(ATTACKER, 80, 10.1))   # now 5 within (0.1, 10.1]
        self.assertIsNotNone(a)

    def test_old_burst_then_quiet_then_new_burst(self):
        e = IDSEngine(cfg(), blocker=MockBlocker())
        for i in range(4):
            e.process_event(ev(ATTACKER, 80, i))
        self.assertIsNone(e.process_event(ev(ATTACKER, 80, 30)))  # old ones expired
        self.assertEqual(len(e.alerts), 0)


SRV_A = "10.0.0.9"
SRV_B = "10.0.0.10"


class TestPortRule(unittest.TestCase):
    """Rule 2 counts distinct dst ports per (src_ip, dst_ip) pair."""

    def test_distinct_ports_trigger_without_rate_rule(self):
        e = IDSEngine(cfg())
        out = [e.process_event(ev(ATTACKER, p, p * 0.1, dst_ip=SRV_A)) for p in (1, 2, 3, 4)]
        a = out[-1]
        self.assertIsNotNone(a)
        self.assertEqual(a.rule, "multi_port_scan")
        self.assertEqual(a.observed_distinct_ports, 4)
        self.assertEqual(a.observed_attempts, 4)
        self.assertIn(SRV_A, a.reason)
        self.assertIn("4 distinct destination ports", a.reason)

    def test_threshold_not_reached_one_below(self):
        e = IDSEngine(cfg())
        for p in (1, 2, 3):
            self.assertIsNone(e.process_event(ev(ATTACKER, p, p * 0.1, dst_ip=SRV_A)))

    def test_same_port_repeated_is_not_a_scan(self):
        e = IDSEngine(cfg(attempts_threshold=100))
        for i in range(20):
            self.assertIsNone(e.process_event(ev(LEGIT, 80, i * 0.1, dst_ip=SRV_A)))

    def test_repeated_ports_do_not_increase_distinct_count(self):
        e = IDSEngine(cfg(attempts_threshold=100))
        # 3 distinct ports on one server, each hit many times -> still 3 < 4
        for i in range(30):
            self.assertIsNone(e.process_event(ev(ATTACKER, 1 + i % 3, i * 0.1, dst_ip=SRV_A)))
        # a 4th distinct port is what finally triggers it
        a = e.process_event(ev(ATTACKER, 4, 3.5, dst_ip=SRV_A))
        self.assertIsNotNone(a)
        self.assertEqual(a.rule, "multi_port_scan")
        self.assertEqual(a.observed_distinct_ports, 4)

    def test_ports_spread_across_servers_do_not_trigger(self):
        e = IDSEngine(cfg(attempts_threshold=100))
        # 8 distinct ports in total, but never more than 3 on any one server
        t = 0.0
        for srv, ports in ((SRV_A, (1, 2, 3)), (SRV_B, (4, 5, 6)), ("10.0.0.11", (7, 8))):
            for p in ports:
                self.assertIsNone(e.process_event(ev(ATTACKER, p, t, dst_ip=srv)))
                t += 0.1
        self.assertEqual(len(e.alerts), 0)

    def test_same_port_set_on_different_servers_not_combined(self):
        e = IDSEngine(cfg(attempts_threshold=100))
        t = 0.0
        for p in (1, 2, 3):                       # 3 ports each on two servers, interleaved
            for srv in (SRV_A, SRV_B):
                self.assertIsNone(e.process_event(ev(ATTACKER, p, t, dst_ip=srv)))
                t += 0.1

    def test_scan_of_one_server_detected_amid_other_server_traffic(self):
        e = IDSEngine(cfg(attempts_threshold=100))
        res = []
        for i, p in enumerate((1, 2, 3, 4)):
            e.process_event(ev(ATTACKER, 80, i * 0.2, dst_ip=SRV_B))       # noise elsewhere (1 port)
            res.append(e.process_event(ev(ATTACKER, p, i * 0.2 + 0.1, dst_ip=SRV_A)))
        a = res[-1]
        self.assertIsNotNone(a)
        self.assertEqual(a.rule, "multi_port_scan")
        self.assertIn(SRV_A, a.reason)
        self.assertEqual(a.observed_distinct_ports, 4)   # per-server count, not 5 overall

    def test_expired_observations_no_longer_count(self):
        e = IDSEngine(cfg(attempts_threshold=100))
        for p in (1, 2, 3):
            self.assertIsNone(e.process_event(ev(ATTACKER, p, p * 0.1, dst_ip=SRV_A)))
        # t=11: ports 1-3 (t<=0.3) are older than W=10 -> expired; only port 4 is live
        self.assertIsNone(e.process_event(ev(ATTACKER, 4, 11.0, dst_ip=SRV_A)))
        self.assertEqual(e.stats["counted_attempts"], 4)
        self.assertEqual(len(e._states[ATTACKER].dst_ports[SRV_A]), 1)
        # two more -> 3 live distinct ports (4,5,6): still below threshold
        self.assertIsNone(e.process_event(ev(ATTACKER, 5, 11.1, dst_ip=SRV_A)))
        self.assertIsNone(e.process_event(ev(ATTACKER, 6, 11.2, dst_ip=SRV_A)))
        # a 4th live distinct port triggers
        self.assertIsNotNone(e.process_event(ev(ATTACKER, 7, 11.3, dst_ip=SRV_A)))

    def test_expiry_is_half_open_per_destination(self):
        e = IDSEngine(cfg(attempts_threshold=100))
        for t, p in ((0.0, 1), (2.0, 2), (4.0, 3)):
            e.process_event(ev(ATTACKER, p, t, dst_ip=SRV_A))
        # at t=10 the t=0 observation is exactly W old -> excluded -> 3 live ports
        self.assertIsNone(e.process_event(ev(ATTACKER, 4, 10.0, dst_ip=SRV_A)))
        # at t=10.1 ports 2,3,4,5 are live (t=2 > 0.1) -> 4 distinct -> fires
        self.assertIsNotNone(e.process_event(ev(ATTACKER, 5, 10.1, dst_ip=SRV_A)))

    def test_expired_destination_state_is_cleaned_up(self):
        e = IDSEngine(cfg(attempts_threshold=100))
        for p in (1, 2):
            e.process_event(ev(ATTACKER, p, p * 0.1, dst_ip=SRV_A))
        e.process_event(ev(ATTACKER, 9, 50.0, dst_ip=SRV_B))
        st = e._states[ATTACKER]
        self.assertNotIn(SRV_A, st.dst_ports)
        self.assertEqual(list(st.dst_ports), [SRV_B])

    def test_missing_dst_ip_does_not_contribute_to_rule2(self):
        e = IDSEngine(cfg(attempts_threshold=100))
        for p in range(1, 30):                    # many distinct ports, no dst_ip
            self.assertIsNone(e.process_event(ev(ATTACKER, p, p * 0.1)))
        self.assertEqual(len(e.alerts), 0)

    def test_missing_dst_ip_events_not_mixed_into_a_servers_count(self):
        e = IDSEngine(cfg(attempts_threshold=100))
        for p in (1, 2, 3):
            self.assertIsNone(e.process_event(ev(ATTACKER, p, p * 0.1, dst_ip=SRV_A)))
        # a 4th distinct port but with unknown destination must NOT complete the set
        self.assertIsNone(e.process_event(ev(ATTACKER, 4, 0.5)))
        a = e.process_event(ev(ATTACKER, 4, 0.6, dst_ip=SRV_A))
        self.assertIsNotNone(a)

    def test_missing_dst_ip_still_counts_for_rate_rule(self):
        e = IDSEngine(cfg())
        res = [e.process_event(ev(ATTACKER, 80, i * 0.1)) for i in range(5)]
        self.assertEqual(res[-1].rule, "high_connection_rate")

    def test_rate_rule_unchanged_with_dst_ip(self):
        e = IDSEngine(cfg())
        res = [e.process_event(ev(ATTACKER, 80, i * 0.1, dst_ip=SRV_A)) for i in range(5)]
        self.assertTrue(all(r is None for r in res[:4]))
        self.assertEqual(res[4].rule, "high_connection_rate")
        self.assertEqual(res[4].observed_attempts, 5)
        self.assertEqual(res[4].observed_distinct_ports, 1)

    def test_rate_rule_counts_across_servers(self):
        # Rule 1 is deliberately NOT per-destination
        e = IDSEngine(cfg())
        srvs = [SRV_A, SRV_B, SRV_A, SRV_B, SRV_A]
        res = [e.process_event(ev(ATTACKER, 80, i * 0.1, dst_ip=s)) for i, s in enumerate(srvs)]
        self.assertEqual(res[-1].rule, "high_connection_rate")

    def test_both_rules_in_one_alert(self):
        e = IDSEngine(cfg(attempts_threshold=4))
        out = [e.process_event(ev(ATTACKER, p, p * 0.1, dst_ip=SRV_A)) for p in (1, 2, 3, 4)]
        self.assertEqual(out[-1].rule, "high_connection_rate+multi_port_scan")
        self.assertEqual(out[-1].observed_attempts, 4)
        self.assertEqual(out[-1].observed_distinct_ports, 4)

    def test_rate_fires_across_servers_but_rule2_does_not(self):
        e = IDSEngine(cfg(attempts_threshold=4))
        out = []
        for i, (srv, p) in enumerate(((SRV_A, 1), (SRV_B, 2), (SRV_A, 3), (SRV_B, 4))):
            out.append(e.process_event(ev(ATTACKER, p, i * 0.1, dst_ip=srv)))
        self.assertEqual(out[-1].rule, "high_connection_rate")

    def test_rule_can_be_disabled(self):
        e = IDSEngine(cfg(port_rule_enabled=False, attempts_threshold=100))
        for p in range(1, 30):
            self.assertIsNone(e.process_event(ev(ATTACKER, p, p * 0.1, dst_ip=SRV_A)))

    def test_incident_reset_clears_per_destination_state(self):
        e = IDSEngine(cfg(), blocker=MockBlocker())
        for p in (1, 2, 3, 4):
            e.process_event(ev(ATTACKER, p, p * 0.1, dst_ip=SRV_A))
        self.assertTrue(e.is_incident_active(ATTACKER))
        # after block_duration (30 s) the incident ends and state is reset
        self.assertIsNone(e.process_event(ev(ATTACKER, 5, 40.0, dst_ip=SRV_A)))
        self.assertEqual(len(e._states[ATTACKER].dst_ports[SRV_A]), 1)

    def test_retransmitted_syn_does_not_add_distinct_ports(self):
        e = IDSEngine(cfg(attempts_threshold=100))
        for t in (0.0, 0.5, 1.0):                 # same 4-tuple within dedup window
            e.process_event(ev(ATTACKER, 80, t, src_port=40000, dst_ip=SRV_A))
        self.assertEqual(e.stats["retransmit_suppressed"], 2)
        self.assertEqual(len(e._states[ATTACKER].dst_ports[SRV_A]), 1)


class TestRetransmitsAndDuplicates(unittest.TestCase):
    def test_retransmitted_syn_counted_once(self):
        e = IDSEngine(cfg())
        for t in (0.0, 0.5, 1.0, 1.5):           # same 4-tuple within 2 s
            e.process_event(ev(ATTACKER, 80, t, src_port=40000, dst_ip="10.0.0.9"))
        self.assertEqual(e.stats["counted_attempts"], 1)
        self.assertEqual(e.stats["retransmit_suppressed"], 3)
        self.assertEqual(len(e.alerts), 0)

    def test_same_tuple_after_retransmit_window_counts_again(self):
        e = IDSEngine(cfg())
        e.process_event(ev(ATTACKER, 80, 0.0, src_port=40000))
        e.process_event(ev(ATTACKER, 80, 2.5, src_port=40000))
        self.assertEqual(e.stats["counted_attempts"], 2)

    def test_without_src_port_no_dedup_possible(self):
        e = IDSEngine(cfg())
        e.process_event(ev(ATTACKER, 80, 0.0))
        e.process_event(ev(ATTACKER, 80, 0.1))
        self.assertEqual(e.stats["counted_attempts"], 2)

    def test_dedup_can_be_disabled(self):
        e = IDSEngine(cfg(retransmit_dedup_enabled=False))
        for t in (0.0, 0.5):
            e.process_event(ev(ATTACKER, 80, t, src_port=40000))
        self.assertEqual(e.stats["counted_attempts"], 2)

    def test_retransmit_flood_does_not_trigger_rate_rule(self):
        e = IDSEngine(cfg())
        for i in range(50):
            e.process_event(ev(ATTACKER, 80, 1.0 + i * 0.01, src_port=40000))
        self.assertEqual(len(e.alerts), 0)

    def test_ip_text_canonicalisation_shares_state(self):
        e = IDSEngine(cfg())
        forms = ["2001:db8::1", "2001:DB8:0:0:0:0:0:1", "2001:0db8::0001",
                 " 2001:db8::1 ", "2001:db8:0::1"]
        res = [e.process_event(ev(f, 80, i * 0.1)) for i, f in enumerate(forms)]
        self.assertIsNotNone(res[-1])
        self.assertEqual(res[-1].src_ip, "2001:db8::1")


class TestMalformedInput(unittest.TestCase):
    BAD = [
        None, "string", 42, [], {},
        {"dst_port": 80, "ts": 1},                              # missing src_ip
        {"src_ip": "10.0.0.2", "ts": 1},                        # missing dst_port
        {"src_ip": "10.0.0.2", "dst_port": 80},                 # missing ts
        {"src_ip": "10.0.0.2", "dst_port": 80, "ts": None},
        {"src_ip": "not-an-ip", "dst_port": 80, "ts": 1},
        {"src_ip": 12345, "dst_port": 80, "ts": 1},
        {"src_ip": "10.0.0.2", "dst_port": 0, "ts": 1},
        {"src_ip": "10.0.0.2", "dst_port": 70000, "ts": 1},
        {"src_ip": "10.0.0.2", "dst_port": "80", "ts": 1},
        {"src_ip": "10.0.0.2", "dst_port": True, "ts": 1},
        {"src_ip": "10.0.0.2", "dst_port": 80, "ts": float("nan")},
        {"src_ip": "10.0.0.2", "dst_port": 80, "ts": float("inf")},
        {"src_ip": "10.0.0.2", "dst_port": 80, "ts": -1},
        {"src_ip": "10.0.0.2", "dst_port": 80, "ts": "1"},
        {"src_ip": "10.0.0.2", "dst_port": 80, "ts": 1, "src_port": -1},
        {"src_ip": "10.0.0.2", "dst_port": 80, "ts": 1, "dst_ip": "bad"},
        {"src_ip": "10.0.0.2", "dst_port": 80, "ts": 1, "tcp_flags": 2},
    ]

    def test_malformed_never_raises_and_is_counted(self):
        e = IDSEngine(cfg())
        for bad in self.BAD:
            self.assertIsNone(e.process_event(bad))
        self.assertEqual(e.stats["malformed"], len(self.BAD))
        self.assertEqual(e.stats["counted_attempts"], 0)
        self.assertEqual(e.active_incidents(), [])

    def test_engine_still_works_after_malformed_input(self):
        e = IDSEngine(cfg())
        for bad in self.BAD:
            e.process_event(bad)
        for i in range(5):
            a = e.process_event(ev(ATTACKER, 80, i * 0.1))
        self.assertIsNotNone(a)

    def test_non_syn_packets_ignored_not_malformed(self):
        e = IDSEngine(cfg())
        for flags in ("SA", "SYN-ACK", "A", "R", "FA", "PA"):
            e.process_event(ev(ATTACKER, 80, 1, tcp_flags=flags))
        self.assertEqual(e.stats["ignored_non_syn"], 6)
        self.assertEqual(e.stats["malformed"], 0)
        self.assertEqual(e.stats["counted_attempts"], 0)

    def test_pure_syn_flags_counted(self):
        e = IDSEngine(cfg())
        for i, flags in enumerate(("S", "SYN", "syn")):
            e.process_event(ev(ATTACKER, 80, i * 0.1, tcp_flags=flags))
        self.assertEqual(e.stats["counted_attempts"], 3)


class TestDeduplicationAndIncidents(unittest.TestCase):
    def trigger(self, e, src=ATTACKER, t0=0.0):
        a = None
        for i in range(5):
            a = e.process_event(ev(src, 80, t0 + i * 0.1))
        return a

    def test_repeated_events_do_not_repeat_alert_or_block(self):
        m = MockBlocker()
        e = IDSEngine(cfg(), blocker=m)
        self.assertIsNotNone(self.trigger(e))
        for i in range(100):
            self.assertIsNone(e.process_event(ev(ATTACKER, 80, 1.0 + i * 0.1)))
        self.assertEqual(len(e.alerts), 1)
        self.assertEqual(len(m.calls), 1)
        self.assertEqual(e.stats["suppressed_during_incident"], 100)

    def test_incident_ends_after_block_duration_then_can_retrigger(self):
        m = MockBlocker()
        e = IDSEngine(cfg(), blocker=m)
        self.trigger(e)                                   # incident ends at ~30.4
        self.assertIsNone(e.process_event(ev(ATTACKER, 80, 40.0)))   # reset, count=1
        self.assertEqual(e.stats["incidents_ended"], 1)
        self.assertFalse(e.is_incident_active(ATTACKER))
        for i in range(1, 5):
            a = e.process_event(ev(ATTACKER, 80, 40.0 + i * 0.1))
        self.assertIsNotNone(a)
        self.assertEqual(a.alert_id, 2)
        self.assertEqual(len(m.calls), 2)

    def test_expire_ends_incident_by_timer(self):
        e = IDSEngine(cfg(), blocker=MockBlocker())
        self.trigger(e)
        self.assertEqual(e.expire(10.0)["incidents_ended"], [])
        self.assertTrue(e.is_incident_active(ATTACKER))
        self.assertEqual(e.expire(100.0)["incidents_ended"], [ATTACKER])
        self.assertFalse(e.is_incident_active(ATTACKER))

    def test_idle_state_is_purged(self):
        e = IDSEngine(cfg())
        e.process_event(ev(LEGIT, 80, 0.0))
        self.assertEqual(e.expire(15.0)["states_purged"], [])   # ttl = max(10, 20) = 20
        self.assertEqual(e.expire(25.0)["states_purged"], [LEGIT])

    def test_legitimate_source_unaffected_by_attacker_incident(self):
        m = MockBlocker()
        e = IDSEngine(cfg(), blocker=m)
        for i in range(5):
            e.process_event(ev(ATTACKER, 80, i * 0.1))
            self.assertIsNone(e.process_event(ev(LEGIT, 80, i * 0.1, src_port=50000 + i)))
        for i in range(5, 20):
            self.assertIsNone(e.process_event(ev(LEGIT, 80, i * 0.5, src_port=50000 + i)))
        self.assertEqual([c[0] for c in m.calls], [ATTACKER])
        self.assertFalse(e.is_incident_active(LEGIT))
        self.assertTrue(e.is_incident_active(ATTACKER))

    def test_whitelist(self):
        m = MockBlocker()
        e = IDSEngine(cfg(whitelist=("10.0.0.254",)), blocker=m)
        for i in range(50):
            self.assertIsNone(e.process_event(ev("10.0.0.254", i + 1, i * 0.01)))
        self.assertEqual(e.stats["whitelisted"], 50)
        self.assertEqual(m.calls, [])

    def test_stale_out_of_order_event_dropped(self):
        e = IDSEngine(cfg())
        e.process_event(ev(LEGIT, 80, 20.0))
        e.process_event(ev(LEGIT, 80, 5.0))      # older than latest - W -> stale
        self.assertEqual(e.stats["stale_dropped"], 1)
        e.process_event(ev(LEGIT, 80, 15.0))     # slightly reordered but in window
        self.assertEqual(e.stats["counted_attempts"], 2)

    def test_on_alert_callback_called_and_faults_contained(self):
        got = []
        e = IDSEngine(cfg(), on_alert=got.append)
        self.trigger(e)
        self.assertEqual(len(got), 1)

        def boom(_):
            raise RuntimeError("callback failure")
        e2 = IDSEngine(cfg(), on_alert=boom)
        self.assertIsNotNone(self.trigger(e2))   # detection still works


class TestBlockerBoundary(unittest.TestCase):
    def trigger(self, e):
        a = None
        for i in range(5):
            a = e.process_event(ev(ATTACKER, 80, i * 0.1))
        return a

    def test_mock_is_labelled_and_never_confirmed(self):
        e = IDSEngine(cfg(), blocker=MockBlocker())
        a = self.trigger(e)
        self.assertEqual(a.block_status, BlockStatus.MOCK_NOT_ENFORCED)
        self.assertFalse(a.is_confirmed_block)
        self.assertIsNotNone(a.block_request_mono)
        self.assertGreaterEqual(a.block_returned_mono, a.block_request_mono)

    def test_block_request_carries_ip_duration_reason(self):
        m = MockBlocker()
        e = IDSEngine(cfg(), blocker=m)
        self.trigger(e)
        ip, dur, reason = m.calls[0]
        self.assertEqual((ip, dur), (ATTACKER, 30.0))
        self.assertIn("connection attempts", reason)

    def test_detection_only_mode_does_not_call_blocker(self):
        m = MockBlocker()
        a = self.trigger(IDSEngine(cfg(), blocker=m, auto_block=False))
        self.assertEqual(m.calls, [])
        self.assertEqual(a.block_status, BlockStatus.NOT_REQUESTED)

    def test_no_blocker_is_detection_only(self):
        a = self.trigger(IDSEngine(cfg()))
        self.assertEqual(a.block_status, BlockStatus.NOT_REQUESTED)

    def test_failed_block_retried_with_cooldown_then_succeeds(self):
        m = MockBlocker(failures=2)
        e = IDSEngine(cfg(), blocker=m)
        a = self.trigger(e)                                  # attempt 1 at ts 0.4 -> FAILED
        self.assertEqual(a.block_status, BlockStatus.FAILED)
        e.process_event(ev(ATTACKER, 80, 1.0))               # inside cooldown -> no retry
        self.assertEqual(len(m.calls), 1)
        e.process_event(ev(ATTACKER, 80, 4.0))               # attempt 2 -> FAILED
        self.assertEqual(len(m.calls), 2)
        e.process_event(ev(ATTACKER, 80, 8.0))               # attempt 3 -> mock success
        self.assertEqual(len(m.calls), 3)
        self.assertEqual(a.block_status, BlockStatus.MOCK_NOT_ENFORCED)
        e.process_event(ev(ATTACKER, 80, 12.0))              # already handled -> no more
        self.assertEqual(len(m.calls), 3)

    def test_retries_are_bounded(self):
        m = MockBlocker(failures=999)
        e = IDSEngine(cfg(), blocker=m)
        self.trigger(e)
        for t in (5, 10, 15, 20, 25):
            e.process_event(ev(ATTACKER, 80, t))
        self.assertEqual(len(m.calls), 3)                    # 1 + block_max_retries

    def test_blocker_exception_is_contained(self):
        e = IDSEngine(cfg(), blocker=MockBlocker(raise_on_call=True))
        a = self.trigger(e)
        self.assertIsNotNone(a)
        self.assertEqual(a.block_status, BlockStatus.FAILED)
        self.assertIn("raised", a.block_detail)

    def test_invalid_blocker_result_treated_as_failure(self):
        class Bad(Blocker):
            def block(self, src_ip, duration_seconds, reason):
                return None
        a = self.trigger(IDSEngine(cfg(), blocker=Bad()))
        self.assertEqual(a.block_status, BlockStatus.FAILED)

    def test_blocker_is_abstract(self):
        with self.assertRaises(TypeError):
            Blocker()  # type: ignore[abstract]

    def test_real_style_blocker_status_is_passed_through_not_upgraded(self):
        class Unverified(Blocker):
            def block(self, src_ip, duration_seconds, reason):
                return BlockResult(BlockStatus.REQUESTED_UNVERIFIED, "flow-mod sent")
        a = self.trigger(IDSEngine(cfg(), blocker=Unverified()))
        self.assertEqual(a.block_status, BlockStatus.REQUESTED_UNVERIFIED)
        self.assertFalse(a.is_confirmed_block)


class TestConfig(unittest.TestCase):
    def test_rules_json_loads(self):
        c = IDSConfig.from_file(os.path.join(HERE, "rules.json"))
        self.assertEqual(c.window_seconds, 10)
        self.assertEqual(c.attempts_threshold, 30)
        self.assertEqual(c.distinct_ports_threshold, 10)

    def test_invalid_values_rejected(self):
        bad = [
            dict(window_seconds=0), dict(window_seconds=-5),
            dict(attempts_threshold=0), dict(attempts_threshold=True),
            dict(distinct_ports_threshold=1.5),
            dict(retransmit_window_seconds=99),
            dict(block_duration_seconds=0), dict(block_max_retries=-1),
            dict(whitelist=("nope",)),
        ]
        for kw in bad:
            with self.assertRaises(ConfigError, msg=str(kw)):
                IDSConfig(**kw)

    def test_unknown_keys_and_bad_types_rejected(self):
        with self.assertRaises(ConfigError):
            IDSConfig.from_dict({"window_secs": 5})
        with self.assertRaises(ConfigError):
            IDSConfig.from_dict({"rules": {"high_connection_rate": {"threshold": 3}}})
        with self.assertRaises(ConfigError):
            IDSConfig.from_dict([])
        IDSConfig.from_dict({"_note": "underscore keys are ignored"})

    def test_missing_or_corrupt_file(self):
        with self.assertRaises(ConfigError):
            IDSConfig.from_file(os.path.join(HERE, "does_not_exist.json"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

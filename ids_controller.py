import csv
import json
import math
import time
from datetime import datetime, timezone
from pathlib import Path

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ether_types, ipv4, packet, tcp

from host_firewall import HOST, MAX_BLOCK_SECONDS, PORT, request_host_block
from ids_engine import Blocker, BlockResult, BlockStatus, IDSConfig, IDSEngine

TCP_SYN = 0x02
TCP_CONNECTION_FLAGS = 0x17  # FIN, SYN, RST, ACK
FLOW_POLL_SECONDS = 2
FLOW_STATS_COLUMNS = (
    "sample_utc", "switch_id", "request_id", "table_id", "priority", "cookie",
    "is_drop", "match", "packet_count", "byte_count", "flow_age_seconds",
)
TIMING_COLUMNS = (
    "run_started_utc", "alert_utc", "alert_id", "source_ip", "destination_ip",
    "rule", "observed_attempts", "distinct_ports", "block_attempt", "block_status",
    "detection_ms", "threshold_processing_ms", "block_call_ms",
    "response_ms", "end_to_end_ms", "detail",
)


def append_csv(path, columns, rows):
    with path.open("a", encoding="utf-8", newline="") as output:
        writer = csv.writer(output)
        if output.tell() == 0:
            writer.writerow(columns)
        writer.writerows(rows)


class RyuSwitchBlocker(Blocker):
    def _init_(self, datapath, logger):
        self.datapath = datapath
        self.logger = logger

    def block(self, src_ip: str, duration_seconds: float, reason: str) -> BlockResult:
        timeout = math.ceil(duration_seconds)
        try:
            request_host_block(src_ip, timeout)
            confirmed_mono = time.monotonic()
        except (OSError, ValueError) as exc:
            detail = f"h1 firewall block failed for {src_ip}: {exc}"
            self.logger.error("%s", detail)
            return BlockResult(BlockStatus.FAILED, detail)

        source = f"h3 ({src_ip})" if src_ip == "10.0.0.3" else src_ip
        self.logger.warning("[BLOCKED] %s -> h1 (%s:%d) for %ds (h1 firewall confirmed)",
                            source, HOST, PORT, timeout)

        datapath = self.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        # h1 is already protected, even if the switch rejects or loses this flow.
        try:
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=HOST,
            )
            datapath.send_msg(parser.OFPFlowMod(
                datapath=datapath,
                table_id=0,
                match=match,
                command=ofproto.OFPFC_ADD,
                hard_timeout=timeout,
                priority=200,
                instructions=[],
            ))
        except Exception:
            self.logger.exception("Could not queue the optional switch drop for %s", src_ip)
            return BlockResult(
                BlockStatus.CONFIRMED, "h1 firewall confirmed; switch update failed", confirmed_mono,
            )
        return BlockResult(
            BlockStatus.CONFIRMED, "h1 firewall confirmed; switch drop requested", confirmed_mono,
        )


class CNProjectController(simple_switch_13.SimpleSwitch13):
    FORWARDING_TABLE = 1

    def start(self):
        project_dir = Path(__file__).resolve().parent
        config = IDSConfig.from_file(project_dir / "rules.json")
        if config.block_duration_seconds > MAX_BLOCK_SECONDS:
            raise ValueError(f"block_duration_seconds must be at most {MAX_BLOCK_SECONDS}")
        self.engine = IDSEngine(config=config, auto_block=True, on_block_result=self._record_intrusion_timing)
        self.run_started_utc = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        self.flow_stats_path = project_dir / "flow_stats.csv"
        self.intrusion_timing_path = project_dir / "intrusion_timing.csv"
        self.stats_datapaths = {}
        self.stats_reporting = set()
        try:
            append_csv(self.flow_stats_path, FLOW_STATS_COLUMNS, ())
        except OSError:
            self.logger.exception("[FLOW STATS] Cannot initialize CSV at %s", self.flow_stats_path)
        else:
            self.logger.info("[FLOW STATS] Collector loaded from %s", Path(__file__).resolve())
            self.logger.info("[FLOW STATS] CSV ready at %s. Waiting for a switch.", self.flow_stats_path)
        try:
            append_csv(self.intrusion_timing_path, TIMING_COLUMNS, ())
        except OSError:
            self.logger.exception("[TIMING] Cannot initialize CSV at %s", self.intrusion_timing_path)
        else:
            self.logger.info("[TIMING] CSV ready at %s. Waiting for an IDS alert.", self.intrusion_timing_path)
        main_thread = super().start()
        self.threads.append(hub.spawn(self._poll_flow_stats))
        return main_thread

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _track_stats_datapath(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if self.stats_datapaths.get(datapath.id) is not datapath:
                self.stats_reporting.discard(datapath.id)
                self.logger.info("[FLOW STATS] Switch %016x connected. Polling every %ds.",
                                 datapath.id, FLOW_POLL_SECONDS)
            self.stats_datapaths[datapath.id] = datapath
        elif self.stats_datapaths.get(datapath.id) is datapath:
            del self.stats_datapaths[datapath.id]
            self.stats_reporting.discard(datapath.id)

    def _poll_flow_stats(self):
        while self.is_active:
            for datapath in tuple(self.stats_datapaths.values()):
                ofproto = datapath.ofproto
                request = datapath.ofproto_parser.OFPFlowStatsRequest(
                    datapath, table_id=ofproto.OFPTT_ALL,
                    out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                )
                datapath.send_msg(request)
            hub.sleep(FLOW_POLL_SECONDS)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _record_flow_stats(self, ev):
        msg = ev.msg
        if not msg.body:
            return
        timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        datapath_id = msg.datapath.id
        switch_id = f"{datapath_id:016x}"
        rows = (
            (
                timestamp, switch_id, msg.xid, flow.table_id, flow.priority,
                f"{flow.cookie:016x}", int(not flow.instructions),
                json.dumps(dict(flow.match.items()), sort_keys=True),
                flow.packet_count, flow.byte_count,
                f"{flow.duration_sec}.{flow.duration_nsec:09d}",
            )
            for flow in msg.body
        )
        try:
            append_csv(self.flow_stats_path, FLOW_STATS_COLUMNS, rows)
        except OSError:
            self.logger.exception("[FLOW STATS] Cannot write to %s", self.flow_stats_path)
        else:
            if datapath_id not in self.stats_reporting:
                self.stats_reporting.add(datapath_id)
                self.logger.info("[FLOW STATS] Wrote first counters from switch %s to %s",
                                 switch_id, self.flow_stats_path)

    def _record_intrusion_timing(self, alert, attempt, result):
        alert_utc = datetime.fromtimestamp(alert.emitted_wall, timezone.utc).isoformat(timespec="milliseconds")
        detection = (alert.emitted_mono - alert.first_event_ts) * 1000
        processing = (alert.emitted_mono - alert.ts) * 1000
        block_call = (alert.block_returned_mono - alert.block_request_mono) * 1000
        response = end_to_end = None
        if result.status == BlockStatus.CONFIRMED and result.confirmed_mono is not None:
            response = (result.confirmed_mono - alert.emitted_mono) * 1000
            end_to_end = (result.confirmed_mono - alert.first_event_ts) * 1000
        row = (
            self.run_started_utc, alert_utc, alert.alert_id, alert.src_ip, HOST, alert.rule,
            alert.observed_attempts, alert.observed_distinct_ports, attempt, result.status.value,
            round(detection, 3), round(processing, 3), round(block_call, 3),
            round(response, 3) if response is not None else None,
            round(end_to_end, 3) if end_to_end is not None else None,
            result.detail,
        )
        try:
            append_csv(self.intrusion_timing_path, TIMING_COLUMNS, (row,))
        except OSError:
            self.logger.exception("[TIMING] Cannot write to %s", self.intrusion_timing_path)
        response_message = f"{response:.3f} ms to confirm h1 block" if response is not None else result.status.value
        self.logger.info("[TIMING] %s alert #%d attempt %d | detection %.3f ms | %s",
                         alert.src_ip, alert.alert_id, attempt, detection, response_message)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        super().switch_features_handler(ev)
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        goto_forwarding = parser.OFPInstructionGotoTable(self.FORWARDING_TABLE)
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, table_id=0, priority=0,
            match=parser.OFPMatch(), instructions=[goto_forwarding],
        ))

        # Mirror SYNs for SDN detection while h1 enforces the rate rule in-kernel.
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP, ip_proto=6, ipv4_dst=HOST,
            tcp_flags=(TCP_SYN, TCP_CONNECTION_FLAGS),
        )
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, table_id=0, priority=10, match=match,
            instructions=[
                parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                goto_forwarding,
            ],
        ))

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Install SimpleSwitch13's table miss and learned flows in table 1."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, table_id=self.FORWARDING_TABLE, priority=priority,
            match=match, instructions=instructions,
            buffer_id=ofproto.OFP_NO_BUFFER if buffer_id is None else buffer_id,
        ))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        observed_at = time.monotonic()
        msg = ev.msg
        if msg.table_id == self.FORWARDING_TABLE:
            super()._packet_in_handler(ev)
            return

        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if (ip_pkt and ip_pkt.dst == HOST and tcp_pkt
                and tcp_pkt.bits & TCP_CONNECTION_FLAGS == TCP_SYN):
            if self.engine.blocker is None or self.engine.blocker.datapath is not msg.datapath:
                self.engine.blocker = RyuSwitchBlocker(msg.datapath, self.logger)
            alert = self.engine.process_event({
                "src_ip": ip_pkt.src,
                "dst_ip": ip_pkt.dst,
                "src_port": tcp_pkt.sport,
                "dst_port": tcp_pkt.dport,
                "ts": observed_at,
                "tcp_flags": "S",
                "source": "packet_in",
            })
            if alert:
                self.logger.warning("IDS alert for %s: %s (%s)",
                                    alert.src_ip, alert.reason, alert.block_detail)

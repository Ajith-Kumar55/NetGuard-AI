"""
Scapy PCAP Flow Extraction and 41-Feature Vector Engineering Module.
Extracts packets from PCAP/PCAPNG files, reconstructs 5-tuple network flows,
computes traffic statistics, and generates 41-feature vectors for ML inference.
"""

from collections import defaultdict
import os
import sys

# Port-to-Service mapping table
PORT_SERVICE_MAP = {
    80: "http",
    443: "http",
    21: "ftp",
    20: "ftp_data",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain_u",
    110: "pop_3",
    143: "imap",
    70: "gopher",
    79: "finger",
    111: "sunrpc",
    513: "login",
    514: "shell",
}


def extract_flows_from_pcap(pcap_path: str) -> list[dict]:
    """
    Parses PCAP/PCAPNG file using Scapy, groups packets into 5-tuple flows,
    and returns a list of 41-feature dictionary payloads with metadata.
    """
    try:
        from scapy.all import ICMP, IP, TCP, UDP, rdpcap
    except ImportError:
        raise ImportError("Scapy package is required for PCAP parsing. Install via pip install scapy.")

    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        raise ValueError(f"Failed to parse PCAP file with Scapy: {str(e)}")

    if not packets:
        return []

    # Group packets by flow key: (src_ip, dst_ip, src_port, dst_port, proto)
    flows = defaultdict(list)
    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto = "tcp" if TCP in pkt else ("udp" if UDP in pkt else ("icmp" if ICMP in pkt else "other"))

            src_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
            dst_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)

            flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
            flows[flow_key].append(pkt)

    flow_records = []
    total_flows = len(flows)

    for flow_key, pkt_list in flows.items():
        src_ip, dst_ip, src_port, dst_port, proto = flow_key
        start_time = float(pkt_list[0].time)
        end_time = float(pkt_list[-1].time)
        duration = max(0.0, round(end_time - start_time, 4))

        src_bytes = sum(len(p) for p in pkt_list if IP in p and p[IP].src == src_ip)
        dst_bytes = sum(len(p) for p in pkt_list if IP in p and p[IP].dst == src_ip)

        # Service mapping based on destination port
        service = PORT_SERVICE_MAP.get(dst_port, PORT_SERVICE_MAP.get(src_port, "private"))

        # Determine TCP status flag
        flag = "SF"
        syn_count = 0
        rej_count = 0
        for p in pkt_list:
            if TCP in p:
                flags = p[TCP].flags
                if flags & 0x02:  # SYN
                    syn_count += 1
                if flags & 0x04:  # RST
                    rej_count += 1

        if syn_count > 0 and len(pkt_list) == syn_count:
            flag = "S0"
        elif rej_count > 0:
            flag = "REJ"

        # Calculated host and service counters
        count = len(pkt_list)
        srv_count = sum(1 for (s, d, sp, dp, pr), pkts in flows.items() if dp == dst_port or sp == dst_port)
        dst_host_count = sum(1 for (s, d, sp, dp, pr), pkts in flows.items() if d == dst_ip)
        dst_host_srv_count = sum(1 for (s, d, sp, dp, pr), pkts in flows.items() if d == dst_ip and (dp == dst_port or sp == dst_port))

        serror_rate = 1.0 if flag == "S0" else 0.0
        rerror_rate = 1.0 if flag == "REJ" else 0.0

        same_srv_rate = round(srv_count / max(1, count), 4)
        diff_srv_rate = round(max(0.0, 1.0 - same_srv_rate), 4)

        record = {
            "duration": duration,
            "protocol_type": proto,
            "service": service,
            "flag": flag,
            "src_bytes": float(src_bytes),
            "dst_bytes": float(dst_bytes),
            "land": 1 if src_ip == dst_ip and src_port == dst_port else 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 1 if service in ["http", "smtp"] else 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": count,
            "srv_count": srv_count,
            "serror_rate": serror_rate,
            "srv_serror_rate": serror_rate,
            "rerror_rate": rerror_rate,
            "srv_rerror_rate": rerror_rate,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": min(255, dst_host_count),
            "dst_host_srv_count": min(255, dst_host_srv_count),
            "dst_host_same_srv_rate": round(min(1.0, dst_host_srv_count / max(1, dst_host_count)), 4),
            "dst_host_diff_srv_rate": diff_srv_rate,
            "dst_host_same_src_port_rate": 0.0,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": serror_rate,
            "dst_host_srv_serror_rate": serror_rate,
            "dst_host_rerror_rate": rerror_rate,
            "dst_host_srv_rerror_rate": rerror_rate,
            # Flow metadata
            "_source_ip": src_ip,
            "_destination_ip": dst_ip,
            "_source_port": src_port,
            "_destination_port": dst_port,
        }

        flow_records.append(record)

    return flow_records

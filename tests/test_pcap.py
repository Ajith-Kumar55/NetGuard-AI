"""
Unit tests for Scapy PCAP parsing and 41-feature extraction.
"""

import os
import tempfile
import pytest
from src.feature_engineering import extract_flows_from_pcap


def test_pcap_extraction_with_synthetic_pcap():
    try:
        from scapy.all import IP, TCP, wrpcap
    except ImportError:
        pytest.skip("Scapy not installed")

    # Create a small synthetic PCAP file with 2 TCP packets
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".pcap")
    os.close(tmp_fd)
    try:
        pkt1 = IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=12345, dport=80, flags="S")
        pkt2 = IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=12345, dport=80, flags="SA")

        wrpcap(tmp_path, [pkt1, pkt2])

        flows = extract_flows_from_pcap(tmp_path)
        assert isinstance(flows, list)
        assert len(flows) >= 1

        first_flow = flows[0]
        assert "duration" in first_flow
        assert first_flow["protocol_type"] == "tcp"
        assert first_flow["service"] == "http"
        assert first_flow["count"] == 2
        assert first_flow["_source_ip"] == "192.168.1.10"
        assert first_flow["_destination_ip"] == "10.0.0.1"

    finally:
        import gc
        gc.collect()
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

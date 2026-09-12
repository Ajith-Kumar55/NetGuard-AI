"""
PCAP / PCAPNG Ingestion and Flow Extraction Service.
Saves uploaded file bytes to a temporary location, invokes Scapy flow extraction,
and cleans up temporary files safely.
"""

import os
import tempfile
from typing import List, Tuple
from src.feature_engineering import extract_flows_from_pcap


def process_pcap_bytes(file_bytes: bytes, filename: str) -> Tuple[List[dict], dict]:
    """
    Saves bytes to temporary file, parses flows using Scapy, and returns flow records.
    Safely removes temporary file upon completion.
    """
    suffix = ".pcapng" if filename.lower().endswith(".pcapng") else ".pcap"
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=suffix)

    try:
        with os.fdopen(tmp_fd, 'wb') as tmp_file:
            tmp_file.write(file_bytes)

        flow_records = extract_flows_from_pcap(tmp_path)
        if not flow_records:
            raise ValueError("No valid IP network flows could be reconstructed from PCAP file.")

        summary = {"total_flows": len(flow_records)}
        return flow_records, summary

    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

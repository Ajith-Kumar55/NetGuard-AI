"""
Centralized attack mapping and Stage 2 taxonomy rules for NetGuard AI.
Maps granular attack types and feature heuristics into 4 major attack families:
- DoS (Denial of Service)
- Probe (Surveillance / Port Scan)
- R2L (Remote to Local / Unauthorized Access)
- U2R (User to Root / Privilege Escalation)
"""

# Taxonomy dictionary mapping NSL-KDD attack names to attack family
ATTACK_FAMILY_MAP = {
    # DoS Family
    "neptune": "DoS",
    "smurf": "DoS",
    "pod": "DoS",
    "teardrop": "DoS",
    "land": "DoS",
    "back": "DoS",
    "apache2": "DoS",
    "udpstorm": "DoS",
    "processtable": "DoS",
    "mailbomb": "DoS",
    # Probe Family
    "satan": "Probe",
    "ipsweep": "Probe",
    "nmap": "Probe",
    "portsweep": "Probe",
    "mscan": "Probe",
    "saint": "Probe",
    # R2L Family
    "guess_passwd": "R2L",
    "ftp_write": "R2L",
    "imap": "R2L",
    "phf": "R2L",
    "warezclient": "R2L",
    "warezmaster": "R2L",
    "spy": "R2L",
    "multihop": "R2L",
    "named": "R2L",
    "snmpgetattack": "R2L",
    "snmpguess": "R2L",
    "sendmail": "R2L",
    "xlock": "R2L",
    "xsnoop": "R2L",
    # U2R Family
    "buffer_overflow": "U2R",
    "rootkit": "U2R",
    "perl": "U2R",
    "loadmodule": "U2R",
    "httptunnel": "U2R",
    "ps": "U2R",
    "xterm": "U2R",
    "sqlexec": "U2R",
}

STAGE2_CLASSES = ["DoS", "Probe", "R2L", "U2R"]


def heuristic_attack_family(feature_dict: dict) -> tuple[str, float]:
    """
    Deterministic domain heuristic classifier for Stage 2 attack family determination
    when an anomaly is detected.
    Returns (attack_family, confidence_score).
    """
    serror_rate = float(feature_dict.get("serror_rate", 0.0))
    srv_serror_rate = float(feature_dict.get("srv_serror_rate", 0.0))
    count = float(feature_dict.get("count", 0.0))
    diff_srv_rate = float(feature_dict.get("diff_srv_rate", 0.0))
    dst_host_diff_srv_rate = float(feature_dict.get("dst_host_diff_srv_rate", 0.0))
    num_failed_logins = float(feature_dict.get("num_failed_logins", 0.0))
    is_guest_login = float(feature_dict.get("is_guest_login", 0.0))
    root_shell = float(feature_dict.get("root_shell", 0.0))
    su_attempted = float(feature_dict.get("su_attempted", 0.0))
    num_root = float(feature_dict.get("num_root", 0.0))
    hot = float(feature_dict.get("hot", 0.0))
    num_shells = float(feature_dict.get("num_shells", 0.0))
    num_file_creations = float(feature_dict.get("num_file_creations", 0.0))
    flag = str(feature_dict.get("flag", ""))
    service = str(feature_dict.get("service", ""))

    # 1. Check User-to-Root (U2R) indicators
    if root_shell > 0 or su_attempted > 0 or num_root > 0 or num_shells > 0 or (hot > 2 and num_file_creations > 0):
        confidence = min(0.85 + 0.05 * (root_shell + su_attempted + num_root), 0.99)
        return "U2R", round(confidence, 4)

    # 2. Check Remote-to-Local (R2L) indicators
    if is_guest_login > 0 or num_failed_logins > 0 or service in ["ftp", "ftp_data", "imap", "pop_3", "telnet", "smtp"]:
        if num_failed_logins > 0 or is_guest_login > 0:
            return "R2L", 0.94
        if service in ["ftp", "ftp_data", "telnet"]:
            return "R2L", 0.88

    # 3. Check Probe / Port Scanning indicators
    if diff_srv_rate > 0.4 or dst_host_diff_srv_rate > 0.4 or flag in ["RSTR", "RSTO", "SH"]:
        confidence = min(0.80 + max(diff_srv_rate, dst_host_diff_srv_rate) * 0.15, 0.98)
        return "Probe", round(confidence, 4)

    # 4. Check Denial of Service (DoS) indicators
    if serror_rate > 0.3 or srv_serror_rate > 0.3 or count > 50 or flag in ["S0", "S1", "S2", "S3", "REJ"]:
        confidence = min(0.82 + max(serror_rate, srv_serror_rate) * 0.15, 0.99)
        return "DoS", round(confidence, 4)

    # Default fallback for unmapped anomaly
    return "DoS", 0.75

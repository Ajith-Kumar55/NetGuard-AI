"""
Defensive Mitigation Recommendation Engine for NetGuard AI.
Provides actionable rule-based defensive guidelines for security analysts
based on detected attack families (DoS, Probe, R2L, U2R).
"""

MITIGATION_RULES = {
    "DoS": [
        "Investigate abnormal traffic volume and high SYN error rates on the target host.",
        "Consider rate limiting and enabling SYN cookies on network firewalls.",
        "Inspect source IP concentration to identify flood sources or amplification vectors.",
        "Deploy ingress filtering rules to drop malicious payload floods."
    ],
    "Probe": [
        "Inspect target host for active port scanning and reconnaissance behavior.",
        "Review firewall drop logs to evaluate sweep scope and target ports.",
        "Temporarily restrict or rate-limit source host IP executing scan probes."
    ],
    "R2L": [
        "Review authentication logs for failed login attempts or credential brute-forcing.",
        "Inspect exposed services (FTP, SSH, Telnet, HTTP) for unauthorized login sessions.",
        "Enforce multi-factor authentication (MFA) and rotate compromised user credentials."
    ],
    "U2R": [
        "Investigate system audit logs for local privilege escalation or unauthorized root shells.",
        "Inspect endpoint host processes for buffer overflow or binary exploitation indicators.",
        "Isolate affected host immediately from the network if root compromise is suspected."
    ],
}


def get_mitigation_recommendations(attack_family: str) -> list[str]:
    """Returns rule-based defensive guidance list for specified attack family."""
    if not attack_family or attack_family not in MITIGATION_RULES:
        return [
            "Monitor network traffic for unexpected baseline deviations.",
            "Verify endpoint security patches and firewall access control lists."
        ]
    return MITIGATION_RULES[attack_family]

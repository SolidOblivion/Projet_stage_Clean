"""
origin_tracker.py — Helper de catégorisation IP Cloudflare.

Fournit une fonction pure is_cloudflare(ip) utilisée par :
    - pipeline/runner.py  : catégorisation cloudflare_ips / real_ips
    - modules/tech_detector.py : filtrage des IPs leakées via headers HTTP

Plages couvertes : blocs Cloudflare publics les plus utilisés.
Aucun side effect, aucune I/O.
"""

CLOUDFLARE_RANGES = [
    "104.16.", "104.17.", "104.18.", "104.19.",
    "104.20.", "104.21.", "172.64.", "172.65.",
    "172.66.", "172.67.",
    "162.158.", "198.41.", "190.93.", "188.114.",
    "197.234.", "141.101.",
]


def is_cloudflare(ip: str) -> bool:
    """Retourne True si l'IP appartient à un bloc Cloudflare connu."""
    return any(ip.startswith(r) for r in CLOUDFLARE_RANGES)

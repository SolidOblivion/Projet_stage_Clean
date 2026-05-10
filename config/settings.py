import os

from dotenv import load_dotenv


load_dotenv()


MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "asm_project")

TIMEOUT = int(os.getenv("TIMEOUT", 5))
MAX_PORTS = int(os.getenv("MAX_PORTS", 1000))
THREADS = int(os.getenv("THREADS", 10))
MAX_SUBDOMAINS = int(os.getenv("MAX_SUBDOMAINS", 100))
PORT_SCANNER_MODE = os.getenv("PORT_SCANNER_MODE", "thread").strip().lower()
PORT_SCAN_CONCURRENCY = int(os.getenv("PORT_SCAN_CONCURRENCY", 400))

SUBDOMAINS_WORDLIST = [
    "www",
    "mail",
    "ftp",
    "admin",
    "api",
    "dev",
    "staging",
    "test",
    "blog",
    "shop",
    "portal",
    "vpn",
    "ssh",
    "smtp",
    "pop",
    "ns1",
    "ns2",
    "cdn",
    "static",
    "assets",
]

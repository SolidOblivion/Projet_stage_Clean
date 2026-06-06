"""
tech_detector.py — Moteur de détection technologique (mini-Wappalyzer).

Architecture :
    web_signatures.py  →  appliquer_signatures()  →  normaliser_detections()
                                                            ↓
                                                     cpe_mapper.py
                                                            ↓
                                              technology_details + cpe_matches

Ce module ne contient AUCUNE signature en dur.
Toute la connaissance métier est dans modules/signatures/web_signatures.py.
"""

import asyncio
import re
import ssl
from urllib.parse import urlsplit, urlunsplit

import aiohttp
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import warnings
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

from config.settings import SHARE_HTML_WITH_ENDPOINT_DISCOVERY, TECH_HTTP_TIMEOUT
from modules.signatures.web_signatures import WEB_SIGNATURES
from modules.signatures.cpe_mapper import generer_cpe, determiner_cpe_status
from modules.origin_tracker import is_cloudflare

# ──────────────────────────────────────────────────────────────
# CONSTANTES
# ──────────────────────────────────────────────────────────────

PORTS_WEB = {
    80: "http",
    443: "https",
    8080: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    3000: "http-dev",
    5000: "http-dev",
}

# Timeout adaptatif : ports standards -> timeout plein,
# ports alternatifs -> timeout court (rarement actifs, evite les longues attentes)
PORTS_TIMEOUT_OVERRIDE = {
    8080: 3.0,
    8443: 3.0,
    8888: 3.0,
    3000: 3.0,
    5000: 3.0,
}

HEADERS_NAVIGATEUR = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
}

ORIGIN_HEADERS = [
    "X-Forwarded-For",   # rare : serveurs qui reflètent les headers de requête
    "X-Origin-IP",
    "X-Real-IP",
    "CF-Connecting-IP",
    "X-Backend-Server",  # expose hostname/IP du backend origine
    "X-Served-By",       # expose IP du nœud réel derrière le CDN
]

MAX_RESPONSE_SIZE = 500_000

# Longueur max d'une version extraite (défense en profondeur)
# TODO(security) : les versions proviennent de serveurs tiers non fiables
MAX_VERSION_LENGTH = 32


def normaliser_url_service(url):
    if not url:
        return None

    parsed = urlsplit(url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None

    path = parsed.path or "/"
    if len(path) > 1:
        path = path.rstrip("/")

    return urlunsplit((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        path,
        parsed.query,
        "",
    ))


# ──────────────────────────────────────────────────────────────
# PRÉ-COMPILATION DES REGEX (évite un ReDoS à chaque requête)
# ──────────────────────────────────────────────────────────────

_COMPILED_SIGNATURES = []

def _compiler_signatures():
    """Compile toutes les regex des signatures au chargement du module."""
    for sig in WEB_SIGNATURES:
        compiled = {
            "name": sig["name"],
            "category": sig.get("category", "unknown"),
            "detection": {},
        }

        detection = sig.get("detection", {})

        # header_regex : {header_name: pattern}
        if "header_regex" in detection:
            compiled["detection"]["header_regex"] = {
                header: re.compile(pattern, re.IGNORECASE)
                for header, pattern in detection["header_regex"].items()
            }

        # meta_regex : {meta_name: pattern}
        if "meta_regex" in detection:
            compiled["detection"]["meta_regex"] = {
                meta: re.compile(pattern, re.IGNORECASE)
                for meta, pattern in detection["meta_regex"].items()
            }

        # script_regex : [pattern, ...]
        if "script_regex" in detection:
            compiled["detection"]["script_regex"] = [
                re.compile(pattern, re.IGNORECASE)
                for pattern in detection["script_regex"]
            ]

        # html_version_regex : extraire une version directement du HTML brut
        if "html_version_regex" in detection:
            compiled["detection"]["html_version_regex"] = [
                re.compile(pattern, re.IGNORECASE)
                for pattern in detection["html_version_regex"]
            ]

        # Les types non-regex sont copiés tels quels
        for key in ("header_contains", "html_contains", "cookie_contains"):
            if key in detection:
                compiled["detection"][key] = detection[key]

        _COMPILED_SIGNATURES.append(compiled)


# Compilation au chargement
_compiler_signatures()


# ──────────────────────────────────────────────────────────────
# FONCTIONS DU MOTEUR
# ──────────────────────────────────────────────────────────────

def creer_detection(name, version, source, confidence, evidence):
    """
    Crée une détection structurée normalisée.

    Args:
        name       : Nom canonique de la technologie
        version    : Version détectée (str ou None)
        source     : Source de détection (ex: "header:server", "meta:generator")
        confidence : Niveau de confiance ("high", "medium", "low")
        evidence   : Preuve brute (la chaîne qui a déclenché la détection)

    Returns:
        dict avec les champs standardisés
    """
    if version:
        version = str(version)[:MAX_VERSION_LENGTH]

    return {
        "name": name,
        "version": version,
        "source": source,
        "confidence": confidence,
        "evidence": str(evidence)[:200] if evidence else None,
    }


def extraire_version(texte, regex_compile):
    """
    Extrait une version depuis un texte via une regex compilée.

    Le premier groupe de capture (groupe 1) est utilisé comme version.
    Retourne None si pas de match ou pas de groupe.
    """
    if not texte or not regex_compile:
        return None

    match = regex_compile.search(texte)
    if match and match.lastindex and match.lastindex >= 1:
        version = match.group(1)
        if version:
            return version[:MAX_VERSION_LENGTH]
    return None


def creer_contexte_ssl_permissif():
    """Crée un contexte SSL qui accepte tous les certificats."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ──────────────────────────────────────────────────────────────
# APPLICATION DES SIGNATURES
# ──────────────────────────────────────────────────────────────

def appliquer_signatures(headers, cookies_str, html, meta_tags, scripts_src):
    """
    Applique toutes les signatures compilées sur les données brutes.

    Args:
        headers     : dict des headers HTTP (clé = nom, valeur = valeur)
        cookies_str : chaîne brute du header Set-Cookie
        html        : contenu HTML brut (str)
        meta_tags   : dict {meta_name: meta_content} extrait par BeautifulSoup
        scripts_src : list des attributs src des balises <script>

    Returns:
        list de détections brutes (avant normalisation)
    """
    # HTTP headers sont case-insensitive (RFC 7230) — normaliser en minuscules
    # pour un lookup fiable quelle que soit la casse retournée par le serveur
    headers_lower = {k.lower(): v for k, v in headers.items()}

    detections = []
    html_lower = html.lower() if html else ""
    cookies_lower = cookies_str.lower() if cookies_str else ""


    for sig in _COMPILED_SIGNATURES:
        name = sig["name"]
        detection = sig["detection"]

        # ── header_contains ──
        if "header_contains" in detection:
            for header_name, expected_substr in detection["header_contains"].items():
                header_val = headers_lower.get(header_name.lower(), "")
                if not header_val:
                    continue
                # Si expected_substr est vide, la simple présence du header suffit
                if expected_substr == "" or expected_substr.lower() in header_val.lower():
                    detections.append(creer_detection(
                        name=name,
                        version=None,
                        source=f"header:{header_name.lower()}",
                        confidence="high",
                        evidence=f"{header_name}: {header_val[:100]}",
                    ))

        # ── header_regex ──
        if "header_regex" in detection:
            for header_name, regex in detection["header_regex"].items():
                header_val = headers_lower.get(header_name.lower(), "")
                if not header_val:
                    continue
                version = extraire_version(header_val, regex)
                if regex.search(header_val):
                    detections.append(creer_detection(
                        name=name,
                        version=version,
                        source=f"header:{header_name.lower()}",
                        confidence="high",
                        evidence=f"{header_name}: {header_val[:100]}",
                    ))

        # ── meta_regex ──
        if "meta_regex" in detection:
            for meta_name, regex in detection["meta_regex"].items():
                meta_content = meta_tags.get(meta_name.lower(), "")
                if not meta_content:
                    continue
                version = extraire_version(meta_content, regex)
                if regex.search(meta_content):
                    detections.append(creer_detection(
                        name=name,
                        version=version,
                        source=f"meta:{meta_name.lower()}",
                        confidence="high",
                        evidence=meta_content[:100],
                    ))

        # ── html_contains ──
        # IMPORTANT : comparer fragment.lower() contre html_lower
        # pour que les fragments avec majuscules/underscores (__NEXT_DATA__, etc.) matchent
        if "html_contains" in detection:
            for fragment in detection["html_contains"]:
                if fragment.lower() in html_lower:
                    detections.append(creer_detection(
                        name=name,
                        version=None,
                        source="html",
                        confidence="medium",
                        evidence=f"'{fragment}' found in HTML",
                    ))
                    # Un seul match HTML suffit pour cette techno
                    break

        # ── html_version_regex ── (extraction de version depuis le HTML brut)
        if "html_version_regex" in detection:
            for regex in detection["html_version_regex"]:
                version = extraire_version(html, regex)  # cherche dans le HTML original (pas lower)
                if version:
                    detections.append(creer_detection(
                        name=name,
                        version=version,
                        source="html",
                        confidence="medium",
                        evidence=f"version {version} found in HTML",
                    ))
                    break

        # ── script_regex ──
        if "script_regex" in detection:
            for regex in detection["script_regex"]:
                for src in scripts_src:
                    version = extraire_version(src, regex)
                    if regex.search(src):
                        detections.append(creer_detection(
                            name=name,
                            version=version,
                            source="script",
                            confidence="medium",
                            evidence=f"src={src[:100]}",
                        ))
                        break  # Un seul match script suffit
                else:
                    continue
                break  # Sortir de la boucle regex aussi

        # ── cookie_contains ──
        if "cookie_contains" in detection:
            for cookie_name, _ in detection["cookie_contains"].items():
                if cookie_name.lower() in cookies_lower:
                    detections.append(creer_detection(
                        name=name,
                        version=None,
                        source="cookie",
                        confidence="medium",
                        evidence=f"Cookie '{cookie_name}' present",
                    ))
                    break  # Un seul cookie suffit

    return detections


# ──────────────────────────────────────────────────────────────
# NORMALISATION
# ──────────────────────────────────────────────────────────────

def normaliser_detections(detections):
    """
    Fusionne et dédoublonne les détections.

    Règles :
        - Clé de fusion = (name, version) — deux versions ≠ doublons
        - Les sources sont agrégées en liste
        - La confiance la plus haute est conservée
        - L'evidence la plus informative est conservée
        - Le CPE est calculé après fusion

    Returns:
        list de détections normalisées avec CPE
    """
    CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}

    # Regrouper par (name, version)
    merged = {}
    for det in detections:
        key = (det["name"], det["version"])

        if key not in merged:
            merged[key] = {
                "name": det["name"],
                "version": det["version"],
                "sources": [],
                "confidence": det["confidence"],
                "evidence": det["evidence"],
            }

        entry = merged[key]

        # Ajouter la source si pas déjà présente
        if det["source"] not in entry["sources"]:
            entry["sources"].append(det["source"])

        # Garder la confiance la plus haute
        if CONFIDENCE_RANK.get(det["confidence"], 0) > CONFIDENCE_RANK.get(entry["confidence"], 0):
            entry["confidence"] = det["confidence"]
            entry["evidence"] = det["evidence"]

    # Enrichir avec les CPE
    result = []
    for entry in merged.values():
        cpe = generer_cpe(entry["name"], entry["version"])
        cpe_status = determiner_cpe_status(entry["name"], cpe)

        result.append({
            "name": entry["name"],
            "version": entry["version"],
            "sources": entry["sources"],
            "confidence": entry["confidence"],
            "evidence": entry["evidence"],
            "cpe": cpe,
            "cpe_status": cpe_status,
        })

    # Trier : high d'abord, puis par nom
    result.sort(key=lambda d: (-CONFIDENCE_RANK.get(d["confidence"], 0), d["name"]))

    return result


# ──────────────────────────────────────────────────────────────
# POINT D'ENTRÉE PRINCIPAL
# ──────────────────────────────────────────────────────────────

def detecter_depuis_reponse(headers, html):
    """
    Point d'entrée unique de détection.

    Parse le HTML avec BeautifulSoup, extrait les balises meta et scripts,
    puis applique les signatures et normalise les résultats.

    Args:
        headers : dict des headers HTTP
        html    : contenu HTML brut (str)

    Returns:
        tuple (technologies, technology_details)
            technologies      : list[str] — noms seuls (rétrocompatibilité)
            technology_details : list[dict] — détections structurées complètes
    """
    # Extraire les meta tags avec BeautifulSoup
    meta_tags = {}
    scripts_src = []

    if html:
        soup = BeautifulSoup(html, "html.parser")

        # Meta tags
        for meta in soup.find_all("meta", attrs={"name": True}):
            nom = meta.get("name", "").lower()
            contenu = meta.get("content", "")
            if nom and contenu:
                meta_tags[nom] = contenu

        # Scripts src
        for script in soup.find_all("script", src=True):
            src = script.get("src", "")
            if src:
                scripts_src.append(src)

    # Cookies depuis les headers (lookup case-insensitive)
    headers_ci = {k.lower(): v for k, v in headers.items()}
    cookies_str = headers_ci.get("set-cookie", "")

    # Appliquer les signatures
    detections_brutes = appliquer_signatures(
        headers=headers,
        cookies_str=cookies_str,
        html=html or "",
        meta_tags=meta_tags,
        scripts_src=scripts_src,
    )

    # Normaliser
    technology_details = normaliser_detections(detections_brutes)

    # Extraire les noms seuls (rétrocompatibilité)
    technologies = list(dict.fromkeys(d["name"] for d in technology_details))

    return technologies, technology_details


# ──────────────────────────────────────────────────────────────
# WRAPPERS LEGACY — Rétrocompatibilité
# ──────────────────────────────────────────────────────────────

def analyser_headers(headers):
    """
    Legacy wrapper — rétrocompatibilité.

    Retourne une liste de noms de technologies détectées via les headers.
    Utilise désormais le moteur de signatures en interne.
    """
    detections = appliquer_signatures(
        headers=headers,
        cookies_str="",
        html="",
        meta_tags={},
        scripts_src=[],
    )
    return list(dict.fromkeys(d["name"] for d in detections))


def analyser_cookies(headers):
    """
    Legacy wrapper — rétrocompatibilité.

    Retourne une liste de noms de technologies détectées via les cookies.
    """
    cookies_str = headers.get("Set-Cookie", "")
    detections = appliquer_signatures(
        headers={},
        cookies_str=cookies_str,
        html="",
        meta_tags={},
        scripts_src=[],
    )
    return list(dict.fromkeys(d["name"] for d in detections))


def analyser_html(html):
    """
    Legacy wrapper — rétrocompatibilité.

    Retourne une liste de noms de technologies détectées via le HTML.
    """
    meta_tags = {}
    scripts_src = []

    if html:
        soup = BeautifulSoup(html, "html.parser")
        for meta in soup.find_all("meta", attrs={"name": True}):
            nom = meta.get("name", "").lower()
            contenu = meta.get("content", "")
            if nom and contenu:
                meta_tags[nom] = contenu
        for script in soup.find_all("script", src=True):
            src = script.get("src", "")
            if src:
                scripts_src.append(src)

    detections = appliquer_signatures(
        headers={},
        cookies_str="",
        html=html or "",
        meta_tags=meta_tags,
        scripts_src=scripts_src,
    )
    return list(dict.fromkeys(d["name"] for d in detections))


# ──────────────────────────────────────────────────────────────
# VISITE ASYNC D'UN SERVICE WEB
# ──────────────────────────────────────────────────────────────

async def visiter_service_async(session, sous_domaine, port, ssl_ctx):
    """
    Visite un service web et retourne les technologies détectées.

    Retourne un dict enrichi avec :
        - technologies       : list[str] (rétrocompatibilité)
        - technology_details : list[dict] (détections structurées + CPE)
    """
    if port in [443, 8443]:
        url = f"https://{sous_domaine}:{port}"
    else:
        url = f"http://{sous_domaine}:{port}"

    if port == 80:
        url = f"http://{sous_domaine}"
    if port == 443:
        url = f"https://{sous_domaine}"

    timeout_port = PORTS_TIMEOUT_OVERRIDE.get(port, TECH_HTTP_TIMEOUT)

    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout_port),
            ssl=ssl_ctx,
            allow_redirects=True,
            headers=HEADERS_NAVIGATEUR,
        ) as reponse:
            html_complet = await reponse.text()
            html = html_complet[:MAX_RESPONSE_SIZE]

            # Nouveau moteur de détection
            technologies, technology_details = detecter_depuis_reponse(
                headers=dict(reponse.headers),
                html=html,
            )

            service = {
                "url": url,
                "final_url": str(reponse.url),
                "status_code": reponse.status,
                "technologies": technologies,
                "technology_details": technology_details,
            }

            # ── Détection IPs origine leakées via headers HTTP ──
            # Certains serveurs derrière Cloudflare exposent l'IP réelle
            # dans ces headers. On collecte les IPs non-Cloudflare uniquement.
            for header in ORIGIN_HEADERS:
                header_val = reponse.headers.get(header, "")
                if not header_val:
                    continue
                candidate_ip = header_val.split(",")[0].strip()
                if candidate_ip and not is_cloudflare(candidate_ip):
                    if "leaked_origin_ips" not in service:
                        service["leaked_origin_ips"] = []
                    if candidate_ip not in service["leaked_origin_ips"]:
                        service["leaked_origin_ips"].append(candidate_ip)

            content_type = reponse.headers.get("Content-Type", "")
            if (
                SHARE_HTML_WITH_ENDPOINT_DISCOVERY
                and "text/html" in content_type.lower()
            ):
                service["_html_cache"] = {
                    "url": str(reponse.url),
                    "html": html,
                    "status_code": reponse.status,
                    "content_type": content_type,
                }

            return service

    except Exception as e:
        print(
            f"     {url} : {type(e).__name__} {repr(e)} "
            f"(timeout={timeout_port}s)"
        )
        return None


# ──────────────────────────────────────────────────────────────
# ORCHESTRATEUR DE DÉTECTION
# ──────────────────────────────────────────────────────────────

async def detecter_technologies(sous_domaines_scannes):
    """
    Détecte les technologies pour tous les sous-domaines scannés.

    Pour chaque sous-domaine, visite tous les ports web ouverts
    et applique le moteur de signatures.
    """
    print("\nDétection des technologies...")

    ssl_ctx = creer_contexte_ssl_permissif()
    resultats = []

    connector = aiohttp.TCPConnector(
        resolver=aiohttp.resolver.ThreadedResolver()
    )

    async with aiohttp.ClientSession(connector=connector) as session:
        for entree in sous_domaines_scannes:
            sous_domaine = entree["subdomain"]
            ports_par_ip = entree["ports_par_ip"]

            print(f"\n  {sous_domaine}")

            ports_a_visiter = set()
            for ports in ports_par_ip.values():
                for port_info in ports:
                    if port_info["port"] in PORTS_WEB:
                        ports_a_visiter.add(port_info["port"])

            taches_ports = sorted(ports_a_visiter)

            services_web = []
            urls_finales_visitees = set()

            if taches_ports:
                taches_async = [
                    visiter_service_async(session, sous_domaine, port, ssl_ctx)
                    for port in taches_ports
                ]

                resultats_ports = await asyncio.gather(*taches_async)

                for resultat in resultats_ports:
                    if resultat is None:
                        continue

                    final_url_norm = (
                        normaliser_url_service(resultat["final_url"])
                        or resultat["final_url"]
                    )
                    if final_url_norm in urls_finales_visitees:
                        continue

                    urls_finales_visitees.add(final_url_norm)
                    services_web.append(resultat)
                    print(f"     {resultat['technologies']}")
            else:
                print("     aucun port web ouvert")

            entree_enrichie = {
                "subdomain": sous_domaine,
                "ips": entree["ips"],
                "mx": entree["mx"],
                "ns": entree["ns"],
                "cname": entree["cname"],
                "ports_par_ip": ports_par_ip,
                "services_web": services_web,
            }
            if "ip_meta" in entree:
                entree_enrichie["ip_meta"] = entree["ip_meta"]
            resultats.append(entree_enrichie)

    print(f"\nDétection terminée pour {len(resultats)} sous-domaines")
    return resultats

# Trigger reload

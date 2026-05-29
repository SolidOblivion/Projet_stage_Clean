import asyncio
import ssl
import time
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import aiohttp
from bs4 import BeautifulSoup

from config.settings import (
    CRAWL_CONCURRENCY,
    CRAWL_FILTERED_QUERY_PARAMS,
    CRAWL_STATIC_PATH_PREFIXES,
    CRAWL_TIMEOUT,
    MAX_CRAWL_DEPTH,
    MAX_CRAWL_PAGES,
    MAX_CRAWL_RESPONSE_SIZE,
)


COMMON_ENDPOINTS = [
    "/admin", "/login", "/api", "/api/v1", "/wp-admin",
    "/wp-login.php", "/.git/config", "/backup", "/config.php",
    "/robots.txt", "/sitemap.xml", "/swagger.json", "/test",
    "/dashboard", "/administrator", "/server-status",
]

HEADERS_NAVIGATEUR = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
}

SOURCE_ORDER = ("fuzzing", "crawler")


def creer_contexte_ssl_permissif():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def normaliser_url(url, base_url=None):
    if not url:
        return None

    absolue = urljoin(base_url, url) if base_url else url
    parsed = urlsplit(absolue.strip())

    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.netloc:
        return None

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    path = path.lower()
    if len(path) > 1:
        path = path.rstrip("/")

    # Seuls les noms de query params configurés sont filtrés ; le path reste intact.
    query_items = [
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if key.lower() not in CRAWL_FILTERED_QUERY_PARAMS
    ]
    query = urlencode(sorted(query_items)) if query_items else ""

    return urlunsplit((scheme, netloc, path, query, ""))


def est_ressource_statique(url):
    parsed = urlsplit(url)
    path = (parsed.path or "").lower()
    return any(path.startswith(prefix) for prefix in CRAWL_STATIC_PATH_PREFIXES)


def est_url_interne(url, base_url):
    url_norm = normaliser_url(url)
    base_norm = normaliser_url(base_url)
    if not url_norm or not base_norm:
        return False
    return urlsplit(url_norm).netloc == urlsplit(base_norm).netloc


def chemin_depuis_url(url):
    parsed = urlsplit(url)
    path = parsed.path or "/"
    return f"{path}?{parsed.query}" if parsed.query else path


def classifier_endpoint(path, status_code=None):
    path_lower = (path or "").lower()

    if status_code in (301, 302, 303, 307, 308):
        return "redirect"
    if status_code == 403:
        return "forbidden"
    if "/api" in path_lower or "/graphql" in path_lower:
        return "api"
    if path_lower.endswith((".json", ".xml", ".yml", ".yaml")):
        return "data_file"
    if any(marker in path_lower for marker in (".env", ".git", "backup", "config.php")):
        return "sensitive"
    if any(marker in path_lower for marker in ("admin", "dashboard", "login")):
        return "admin_panel"

    return "page"


def creer_endpoint(url, status_code, source):
    path = chemin_depuis_url(url)
    return {
        "path": path,
        "url": url,
        "status_code": status_code,
        "source": source,
        "category": classifier_endpoint(path, status_code),
    }


async def lire_html_borne(reponse):
    contenu = await reponse.content.read(MAX_CRAWL_RESPONSE_SIZE)
    charset = reponse.charset or "utf-8"
    return contenu.decode(charset, errors="replace")


async def tester_endpoint(session, base_url, endpoint, ssl_ctx, semaphore):
    url_a_tester = normaliser_url(endpoint, base_url)
    if not url_a_tester:
        return None

    async with semaphore:
        try:
            debut = time.perf_counter()
            async with session.head(
                url_a_tester,
                timeout=aiohttp.ClientTimeout(total=CRAWL_TIMEOUT),
                ssl=ssl_ctx,
                allow_redirects=False,
                headers=HEADERS_NAVIGATEUR,
            ) as reponse:
                status = reponse.status
            duree = time.perf_counter() - debut

            if status in (405, 501):
                debut = time.perf_counter()
                async with session.get(
                    url_a_tester,
                    timeout=aiohttp.ClientTimeout(total=CRAWL_TIMEOUT),
                    ssl=ssl_ctx,
                    allow_redirects=False,
                    headers=HEADERS_NAVIGATEUR,
                ) as reponse_get:
                    status = reponse_get.status
                duree += time.perf_counter() - debut

            if status in (200, 301, 302, 303, 307, 308, 403):
                endpoint_trouve = creer_endpoint(url_a_tester, status, "fuzzing")
                endpoint_trouve["_perf_duration"] = duree
                return endpoint_trouve

        except Exception as e:
            print(f"        [fuzzing] {url_a_tester} : {type(e).__name__} {repr(e)}")

    return None


async def fuzzer_endpoints(session, service, ssl_ctx, semaphore):
    base_url = service.get("url")
    debut = time.perf_counter()
    print(f"     -> Fuzzing sur {base_url} ({len(COMMON_ENDPOINTS)} tests)")

    resultats = await asyncio.gather(
        *[
            tester_endpoint(session, base_url, endpoint, ssl_ctx, semaphore)
            for endpoint in COMMON_ENDPOINTS
        ]
    )
    endpoints = [res for res in resultats if res is not None]
    print(
        f"        [PERF][fuzzing] url={base_url} tests={len(COMMON_ENDPOINTS)} "
        f"trouves={len(endpoints)} duree={time.perf_counter() - debut:.2f}s"
    )
    return endpoints


def extraire_liens_html(html, base_url):
    if not html:
        return set(), 0.0

    debut = time.perf_counter()
    soup = BeautifulSoup(html, "html.parser")
    candidats = []

    for tag in soup.find_all("a", href=True):
        candidats.append(tag.get("href"))
    for tag in soup.find_all("form", action=True):
        candidats.append(tag.get("action"))

    liens = set()
    for candidat in candidats:
        url = normaliser_url(candidat, base_url)
        if url and est_url_interne(url, base_url) and not est_ressource_statique(url):
            liens.add(url)

    return liens, time.perf_counter() - debut


async def recuperer_page_html(session, url, ssl_ctx, semaphore):
    async with semaphore:
        try:
            debut = time.perf_counter()
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=CRAWL_TIMEOUT),
                ssl=ssl_ctx,
                allow_redirects=True,
                headers=HEADERS_NAVIGATEUR,
            ) as reponse:
                content_type = reponse.headers.get("Content-Type", "")
                html = ""
                if "text/html" in content_type.lower():
                    html = await lire_html_borne(reponse)

                return {
                    "url": normaliser_url(str(reponse.url)) or url,
                    "status_code": reponse.status,
                    "content_type": content_type,
                    "html": html,
                    "duration": time.perf_counter() - debut,
                }

        except Exception as e:
            print(f"        [crawler] {url} : {type(e).__name__} {repr(e)}")
            return None


async def crawler_endpoints(session, service, ssl_ctx, semaphore):
    debut_total = time.perf_counter()
    base_url = normaliser_url(service.get("final_url") or service.get("url"))
    if not base_url:
        return []

    print(
        f"     -> Crawling sur {base_url} "
        f"(depth={MAX_CRAWL_DEPTH}, max_pages={MAX_CRAWL_PAGES})"
    )

    endpoints = []
    visited_urls = set()
    queued_urls = set()
    queue = []
    pages_get = 0
    cache_used = False
    parse_time = 0.0
    http_time = 0.0
    max_queue = 0

    cache = service.get("_html_cache")
    if cache and "text/html" in cache.get("content_type", "").lower():
        cache_used = True
        cache_url = normaliser_url(cache.get("url") or base_url) or base_url
        visited_urls.add(cache_url)
        endpoints.append(creer_endpoint(cache_url, cache.get("status_code"), "crawler"))
        liens, duree_parse = extraire_liens_html(cache.get("html", ""), cache_url)
        parse_time += duree_parse
        for lien in liens:
            if lien not in queued_urls and lien not in visited_urls:
                queue.append((lien, 1))
                queued_urls.add(lien)
        print(f"        [crawler] cache HTML reutilise : {len(liens)} liens")
    else:
        queue.append((base_url, 0))
        queued_urls.add(base_url)

    while queue and len(visited_urls) < MAX_CRAWL_PAGES:
        max_queue = max(max_queue, len(queue))
        batch = []

        while (
            queue
            and len(batch) < CRAWL_CONCURRENCY
            and len(visited_urls) + len(batch) < MAX_CRAWL_PAGES
        ):
            url, depth = queue.pop(0)
            if url in visited_urls or depth > MAX_CRAWL_DEPTH:
                continue
            batch.append((url, depth))

        if not batch:
            continue

        pages = await asyncio.gather(
            *[
                recuperer_page_html(session, url, ssl_ctx, semaphore)
                for url, _depth in batch
            ]
        )

        for (_url, depth), page in zip(batch, pages):
            if page is None:
                continue

            pages_get += 1
            http_time += page.get("duration", 0.0)
            page_url = page["url"]
            if page_url in visited_urls:
                continue

            visited_urls.add(page_url)
            endpoints.append(creer_endpoint(page_url, page["status_code"], "crawler"))

            if depth >= MAX_CRAWL_DEPTH:
                continue

            liens, duree_parse = extraire_liens_html(page.get("html", ""), page_url)
            parse_time += duree_parse
            for lien in liens:
                if len(visited_urls) + len(queue) >= MAX_CRAWL_PAGES:
                    break
                if lien in visited_urls or lien in queued_urls:
                    continue
                queue.append((lien, depth + 1))
                queued_urls.add(lien)

    print(
        f"        [PERF][crawler] url={base_url} cache={cache_used} "
        f"get={pages_get} endpoints={len(endpoints)} visited={len(visited_urls)} "
        f"max_queue={max_queue} http={http_time:.2f}s parse={parse_time:.2f}s "
        f"total={time.perf_counter() - debut_total:.2f}s"
    )
    return endpoints


def fusionner_endpoints(*listes):
    debut = time.perf_counter()
    fusion = {}

    for endpoints in listes:
        for endpoint in endpoints:
            url = normaliser_url(endpoint.get("url"))
            if not url:
                continue

            existant = fusion.get(url)
            if existant is None:
                fusion[url] = {
                    "path": chemin_depuis_url(url),
                    "url": url,
                    "status_code": endpoint.get("status_code"),
                    "source": endpoint.get("source", "unknown"),
                    "category": endpoint.get("category")
                    or classifier_endpoint(chemin_depuis_url(url), endpoint.get("status_code")),
                }
                continue

            sources = set(existant.get("source", "").split("+"))
            sources.update(endpoint.get("source", "unknown").split("+"))
            existant["source"] = normaliser_sources(sources)

            if existant.get("status_code") is None:
                existant["status_code"] = endpoint.get("status_code")
            existant["category"] = classifier_endpoint(
                existant["path"],
                existant.get("status_code"),
            )

    resultats = sorted(fusion.values(), key=lambda item: (item["category"], item["path"]))
    for endpoint in resultats:
        endpoint.pop("_perf_duration", None)
    print(
        f"        [PERF][fusion] entrees={sum(len(liste) for liste in listes)} "
        f"sorties={len(resultats)} duree={time.perf_counter() - debut:.3f}s"
    )
    return resultats


def normaliser_sources(sources):
    sources = {source for source in sources if source}
    ordonnees = [source for source in SOURCE_ORDER if source in sources]
    ordonnees.extend(sorted(sources.difference(SOURCE_ORDER)))
    return "+".join(ordonnees)


async def decouvrir_endpoints_async(sous_domaines_enrichis):
    debut_global = time.perf_counter()
    print("\nDecouverte des endpoints (Fuzzing + Crawling)...")
    ssl_ctx = creer_contexte_ssl_permissif()
    semaphore = asyncio.Semaphore(CRAWL_CONCURRENCY)
    total_trouves = 0

    connector = aiohttp.TCPConnector(
        resolver=aiohttp.resolver.ThreadedResolver()
    )

    async with aiohttp.ClientSession(connector=connector) as session:
        for entree in sous_domaines_enrichis:
            sous_domaine = entree.get("subdomain")
            services_web = entree.get("services_web", [])

            if services_web:
                print(f"\n  {sous_domaine}")

            for service in services_web:
                debut_service = time.perf_counter()
                endpoints = []
                try:
                    fuzzing = await fuzzer_endpoints(session, service, ssl_ctx, semaphore)
                    crawling = await crawler_endpoints(session, service, ssl_ctx, semaphore)
                    endpoints = fusionner_endpoints(fuzzing, crawling)
                except Exception as e:
                    print(
                        f"        [endpoint_discovery] erreur service "
                        f"{service.get('url')} : {type(e).__name__} {repr(e)}"
                    )
                finally:
                    service.pop("_html_cache", None)

                service["endpoints"] = endpoints
                total_trouves += len(endpoints)

                for ep in endpoints:
                    print(
                        f"        [+] {ep['status_code']} {ep['source']} "
                        f"{ep['category']} : {ep['path']}"
                    )

                if not endpoints:
                    print("        [-] aucun endpoint trouve")
                print(
                    f"        [PERF][service] url={service.get('url')} "
                    f"endpoints={len(endpoints)} total={time.perf_counter() - debut_service:.2f}s"
                )

    print(
        f"\nDecouverte terminee : {total_trouves} endpoints trouves au total "
        f"en {time.perf_counter() - debut_global:.2f}s"
    )
    return sous_domaines_enrichis


def lancer_decouverte_endpoints(sous_domaines_enrichis):
    return asyncio.run(decouvrir_endpoints_async(sous_domaines_enrichis))

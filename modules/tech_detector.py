import asyncio
import ssl

import aiohttp
from bs4 import BeautifulSoup

from config.settings import TIMEOUT


PORTS_WEB = {
    80: "http",
    443: "https",
    8080: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    3000: "http-dev",
    5000: "http-dev",
}

HEADERS_NAVIGATEUR = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
}

MAX_RESPONSE_SIZE = 500_000

CANONICAL_TECHNOLOGIES = {
    "cloudflare": "Cloudflare",
    "aws cloudfront": "AWS CloudFront",
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "next.js": "Next.js",
    "nuxt.js": "Nuxt.js",
    "angular": "Angular",
    "react": "React",
    "vue.js": "Vue.js",
    "jquery": "jQuery",
    "bootstrap": "Bootstrap",
    "google analytics": "Google Analytics",
    "facebook pixel": "Facebook Pixel",
    "shopify": "Shopify",
    "squarespace": "Squarespace",
    "wix": "Wix",
    "php": "PHP",
    "java": "Java",
    "asp.net": "ASP.NET",
    "laravel": "Laravel",
    "django": "Django",
    "ruby on rails": "Ruby on Rails",
}


def creer_contexte_ssl_permissif():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def normaliser_technologies(technologies):
    technologies_normalisees = []
    deja_vues = set()

    for techno in technologies:
        if not techno:
            continue

        techno = techno.strip()
        cle = techno.lower()
        techno_canonique = CANONICAL_TECHNOLOGIES.get(cle, techno)
        cle_canonique = techno_canonique.lower()

        if cle_canonique in deja_vues:
            continue

        deja_vues.add(cle_canonique)
        technologies_normalisees.append(techno_canonique)

    return technologies_normalisees


def analyser_headers(headers):
    technologies = []

    serveur = headers.get("Server", "")
    if serveur:
        technologies.append(serveur)

    powered_by = headers.get("X-Powered-By", "")
    if powered_by:
        technologies.append(powered_by)

    generator = headers.get("X-Generator", "")
    if generator:
        technologies.append(generator)

    via = headers.get("Via", "")
    if "cloudflare" in via.lower():
        technologies.append("Cloudflare")

    if "CF-RAY" in headers and "Cloudflare" not in technologies:
        technologies.append("Cloudflare")

    if "X-Amz-Cf-Id" in headers:
        technologies.append("AWS CloudFront")

    return technologies


def analyser_cookies(headers):
    technologies = []

    signatures_cookies = {
        "PHPSESSID": "PHP",
        "JSESSIONID": "Java",
        "ASP.NET_SessionId": "ASP.NET",
        "laravel_session": "Laravel",
        "django_session": "Django",
        "rack.session": "Ruby on Rails",
    }

    set_cookie = headers.get("Set-Cookie", "")

    for signature, techno in signatures_cookies.items():
        if signature.lower() in set_cookie.lower() and techno not in technologies:
            technologies.append(techno)

    return technologies


def analyser_html(html):
    technologies = []
    soup = BeautifulSoup(html, "html.parser")

    meta_generator = soup.find("meta", {"name": "generator"})
    if meta_generator:
        contenu = meta_generator.get("content", "")
        if contenu:
            technologies.append(contenu)

    signatures_scripts = {
        "wp-content": "WordPress",
        "wp-includes": "WordPress",
        "sites/all": "Drupal",
        "sites/default": "Drupal",
        "_next": "Next.js",
        "nuxt": "Nuxt.js",
        "angular": "Angular",
        "react": "React",
        "vue": "Vue.js",
        "jquery": "jQuery",
        "bootstrap": "Bootstrap",
    }

    scripts = soup.find_all("script", src=True)
    for script in scripts:
        src = script.get("src", "").lower()
        for signature, techno in signatures_scripts.items():
            if signature in src and techno not in technologies:
                technologies.append(techno)

    html_lower = html.lower()

    signatures_html = {
        "wp-json": "WordPress",
        "shopify.com/s/files": "Shopify",
        "cdn.shopify": "Shopify",
        "squarespace": "Squarespace",
        "wix.com": "Wix",
        "gtag": "Google Analytics",
        "google-analytics": "Google Analytics",
        "fbq(": "Facebook Pixel",
    }

    for signature, techno in signatures_html.items():
        if signature in html_lower and techno not in technologies:
            technologies.append(techno)

    return technologies


async def visiter_service_async(session, sous_domaine, port, ssl_ctx):
    if port in [443, 8443]:
        url = f"https://{sous_domaine}:{port}"
    else:
        url = f"http://{sous_domaine}:{port}"

    if port == 80:
        url = f"http://{sous_domaine}"
    if port == 443:
        url = f"https://{sous_domaine}"

    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=TIMEOUT),
            ssl=ssl_ctx,
            allow_redirects=True,
            headers=HEADERS_NAVIGATEUR,
        ) as reponse:
            html_complet = await reponse.text()
            html = html_complet[:MAX_RESPONSE_SIZE]

            techs_headers = analyser_headers(dict(reponse.headers))
            techs_cookies = analyser_cookies(dict(reponse.headers))
            techs_html = analyser_html(html)

            toutes_les_techs = normaliser_technologies(
                techs_headers + techs_cookies + techs_html
            )

            return {
                "url": url,
                "final_url": str(reponse.url),
                "status_code": reponse.status,
                "technologies": toutes_les_techs,
            }

    except Exception as e:
        print(f"     {url} : {e}")
        return None


async def detecter_technologies(sous_domaines_scannes):
    print("\nDétection des technologies...")

    ssl_ctx = creer_contexte_ssl_permissif()
    resultats = []

    async with aiohttp.ClientSession() as session:
        for entree in sous_domaines_scannes:
            sous_domaine = entree["subdomain"]
            ports_par_ip = entree["ports_par_ip"]

            print(f"\n  {sous_domaine}")

            taches_ports = []
            for ports in ports_par_ip.values():
                for port_info in ports:
                    if port_info["port"] in PORTS_WEB:
                        taches_ports.append(port_info["port"])

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

                    if resultat["final_url"] in urls_finales_visitees:
                        continue

                    urls_finales_visitees.add(resultat["final_url"])
                    services_web.append(resultat)
                    print(f"     {resultat['technologies']}")
            else:
                print("     aucun port web ouvert")

            resultats.append(
                {
                    "subdomain": sous_domaine,
                    "ips": entree["ips"],
                    "mx": entree["mx"],
                    "ns": entree["ns"],
                    "cname": entree["cname"],
                    "ports_par_ip": ports_par_ip,
                    "services_web": services_web,
                }
            )

    print(f"\nDétection terminée pour {len(resultats)} sous-domaines")
    return resultats

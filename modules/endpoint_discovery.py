import asyncio
import ssl
import aiohttp
from config.settings import TIMEOUT

# Une wordlist courte pour la démonstration (rapide et impactante)
# En production, on chargerait un fichier texte externe de 50 000 lignes.
COMMON_ENDPOINTS = [
    "/admin", "/login", "/api", "/api/v1", "/wp-admin", 
    "/wp-login.php", "/.git/config", "/backup", "/config.php", 
    "/robots.txt", "/sitemap.xml", "/swagger.json", "/test",
    "/dashboard", "/administrator", "/server-status"
]

def creer_contexte_ssl_permissif():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

async def tester_endpoint(session, base_url, endpoint, ssl_ctx):
    url_a_tester = base_url.rstrip('/') + endpoint
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        # On utilise HEAD pour être très rapide (pas besoin de télécharger tout le HTML pour savoir si la page existe)
        async with session.head(
            url_a_tester,
            timeout=aiohttp.ClientTimeout(total=TIMEOUT),
            ssl=ssl_ctx,
            allow_redirects=False,
            headers=headers
        ) as reponse:
            status = reponse.status
            
            # Si le serveur bloque la méthode HEAD (ex: 405 Method Not Allowed), on essaie en GET
            if status in [405, 501]:
                async with session.get(
                    url_a_tester,
                    timeout=aiohttp.ClientTimeout(total=TIMEOUT),
                    ssl=ssl_ctx,
                    allow_redirects=False,
                    headers=headers
                ) as rep_get:
                    status = rep_get.status
                    
            # 200 = Trouvé, 301/302 = Redirection (existe), 403 = Interdit (existe mais protégé)
            if status in [200, 301, 302, 403]:
                return {
                    "path": endpoint,
                    "url": url_a_tester,
                    "status_code": status
                }
    except Exception:
        pass
    
    return None

async def decouvrir_endpoints_async(sous_domaines_enrichis):
    print("\nDécouverte des endpoints (Fuzzing)...")
    ssl_ctx = creer_contexte_ssl_permissif()
    
    total_trouves = 0

    async with aiohttp.ClientSession() as session:
        for entree in sous_domaines_enrichis:
            sous_domaine = entree.get("subdomain")
            services_web = entree.get("services_web", [])
            
            if services_web:
                print(f"\n  {sous_domaine}")
            
            for service in services_web:
                base_url = service.get("url")
                print(f"     -> Fuzzing sur {base_url} ({len(COMMON_ENDPOINTS)} tests en parallèle)")
                
                taches = [
                    tester_endpoint(session, base_url, endpoint, ssl_ctx)
                    for endpoint in COMMON_ENDPOINTS
                ]
                
                resultats = await asyncio.gather(*taches)
                endpoints_valides = [res for res in resultats if res is not None]
                
                # Injection de la liste d'endpoints dans le service web existant
                service["endpoints"] = endpoints_valides
                
                for ep in endpoints_valides:
                    total_trouves += 1
                    print(f"        [+] {ep['status_code']} : {ep['path']}")
                    
                if not endpoints_valides:
                    print("        [-] aucun endpoint critique trouvé")
                    
    print(f"\nDécouverte terminée : {total_trouves} endpoints trouvés au total")
    return sous_domaines_enrichis

def lancer_decouverte_endpoints(sous_domaines_enrichis):
    return asyncio.run(decouvrir_endpoints_async(sous_domaines_enrichis))

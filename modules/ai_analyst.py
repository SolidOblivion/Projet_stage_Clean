"""
ai_analyst.py — Module d'analyse de sécurité par IA.

Reçoit les résultats complets d'un scan ASM et produit un rapport
d'analyse de sécurité structuré en 6 niveaux, comparable à un rapport
de pentest professionnel.

Architecture :
    data_mapper.assembler_resultats()
        → resultat_final (dict)
            → generer_analyse_ia(resultat_final)
                → rapport structuré (str markdown)

Backends supportés : OpenAI, Anthropic, ou tout provider compatible OpenAI.
Configuration via config/settings.py (AI_PROVIDER, AI_MODEL, AI_API_KEY, AI_BASE_URL).
"""

import json
import time
from typing import Any, Dict, Optional

from config.settings import AI_API_KEY, AI_BASE_URL, AI_MODEL, AI_PROVIDER


# ──────────────────────────────────────────────────────────────
# CONSTRUCTION DU CONTEXTE (données scan → texte structuré)
# ──────────────────────────────────────────────────────────────

def _extraire_contexte_scan(scan: Dict[str, Any]) -> str:
    """
    Transforme le dict de résultats du scan en un bloc de texte structuré
    que l'IA peut analyser. On extrait uniquement les données pertinentes
    pour l'analyse de sécurité, pas le HTML brut.
    """
    lignes = []

    # ── Méta ──
    lignes.append(f"CIBLE : {scan.get('target', 'N/A')}")
    lignes.append(f"DATE  : {scan.get('scan_date', 'N/A')}")
    lignes.append(f"MODE  : {scan.get('mode', 'quick')}")
    lignes.append("")

    # ── Summary ──
    summary = scan.get("summary", {})
    lignes.append("=== RÉSUMÉ CHIFFRÉ ===")
    lignes.append(f"Sous-domaines découverts : {summary.get('total_subdomains', 0)}")
    lignes.append(f"IPs uniques exposées     : {summary.get('total_ips', 0)}")
    lignes.append(f"Ports ouverts totaux     : {summary.get('total_open_ports', 0)}")
    lignes.append(f"Technologies détectées   : {summary.get('total_technologies', 0)}")
    lignes.append(f"Endpoints découverts     : {summary.get('total_endpoints', 0)}")
    lignes.append(f"CPE matches              : {summary.get('total_cpe_matches', 0)}")
    lignes.append("")

    # ── CPE Matches globaux ──
    cpe_matches = scan.get("cpe_matches", [])
    if cpe_matches:
        lignes.append("=== CPE MATCHES (technologies avec identifiant CVE explorable) ===")
        for cpe in cpe_matches:
            version_str = f" v{cpe['version']}" if cpe.get("version") else " (version inconnue)"
            lignes.append(
                f"  - {cpe['technology']}{version_str} → {cpe['cpe_uri']} "
                f"[confiance: {cpe.get('confidence', 'N/A')}, trouvé sur: {cpe.get('found_on', 'N/A')}]"
            )
        lignes.append("")

    # ── Détail par sous-domaine ──
    lignes.append("=== DÉTAIL PAR SOUS-DOMAINE ===")

    for sd in scan.get("subdomains", []):
        subdomain = sd.get("subdomain", "N/A")
        ips = sd.get("ips", [])
        dns_info = sd.get("dns", {})
        tags = sd.get("tags", [])
        ip_meta = sd.get("ip_meta", {})

        # Header sous-domaine
        tag_str = f" [TAGS: {', '.join(tags)}]" if tags else ""
        lignes.append(f"\n--- {subdomain}{tag_str} ---")

        # IPs avec métadonnées Cloudflare
        ip_details = []
        for ip in ips:
            cf = ip_meta.get(ip, {}).get("is_cloudflare", False)
            label = f"{ip} (CLOUDFLARE)" if cf else f"{ip} (IP RÉELLE)"
            ip_details.append(label)
        lignes.append(f"  IPs : {', '.join(ip_details) if ip_details else 'aucune'}")

        # DNS
        if dns_info.get("cname"):
            lignes.append(f"  CNAME : {dns_info['cname']}")
        if dns_info.get("mx"):
            mx_str = ", ".join(
                f"{mx['serveur']}" if isinstance(mx, dict) else str(mx)
                for mx in dns_info["mx"]
            )
            lignes.append(f"  MX : {mx_str}")
        if dns_info.get("ns"):
            lignes.append(f"  NS : {', '.join(dns_info['ns'])}")

        # Ports par IP
        ports_par_ip = sd.get("ports_par_ip", {})
        for ip, ports in ports_par_ip.items():
            if not ports:
                continue
            cf_label = " (CLOUDFLARE)" if ip_meta.get(ip, {}).get("is_cloudflare", False) else ""
            ports_str = ", ".join(
                f"{p['port']}/{p.get('protocole', 'tcp')} ({p.get('service', 'unknown')}"
                + (f" v{p['version']}" if p.get('version') else "")
                + (f" banner='{p['banner'][:60]}'" if p.get('banner') else "")
                + ")"
                for p in sorted(ports, key=lambda x: x.get("port", 0))
            )
            lignes.append(f"  Ports sur {ip}{cf_label} : {ports_str}")

        # Services web
        for service in sd.get("services_web", []):
            url = service.get("url", "")
            final_url = service.get("final_url", "")
            status = service.get("status_code", "?")
            redirect_str = f" → redirigé vers {final_url}" if final_url and final_url != url else ""

            lignes.append(f"  Service web : {url} [HTTP {status}]{redirect_str}")

            # Technologies détaillées
            for det in service.get("technology_details", []):
                version_str = f" v{det['version']}" if det.get("version") else ""
                cpe_str = ""
                if det.get("cpe") and det["cpe"].get("uri"):
                    cpe_str = f" CPE={det['cpe']['uri']}"
                lignes.append(
                    f"    Tech : {det['name']}{version_str} "
                    f"[confiance: {det.get('confidence', '?')}, "
                    f"source: {', '.join(det.get('sources', []))}, "
                    f"statut CPE: {det.get('cpe_status', '?')}{cpe_str}]"
                )

            # IPs origine leakées
            for leaked_ip in service.get("leaked_origin_ips", []):
                lignes.append(f"    ⚠ IP ORIGINE LEAKÉE : {leaked_ip}")

            # Endpoints
            endpoints = service.get("endpoints", [])
            if endpoints:
                # Grouper par catégorie pour lisibilité
                by_cat = {}
                for ep in endpoints:
                    cat = ep.get("category", "page")
                    by_cat.setdefault(cat, []).append(ep)

                for cat in ["sensitive", "api", "admin_panel", "data_file", "forbidden", "redirect", "page"]:
                    eps = by_cat.get(cat, [])
                    if not eps:
                        continue
                    ep_strs = [
                        f"{ep['path']} [{ep.get('status_code', '?')}] ({ep.get('source', '?')})"
                        for ep in eps[:15]  # Limiter pour ne pas exploser le contexte
                    ]
                    overflow = f" (+{len(eps) - 15} autres)" if len(eps) > 15 else ""
                    lignes.append(f"    Endpoints [{cat.upper()}] : {'; '.join(ep_strs)}{overflow}")

    return "\n".join(lignes)


# ──────────────────────────────────────────────────────────────
# PROMPT SYSTÈME
# ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
Tu es un Security Analyst Assistant spécialisé en Attack Surface Management.
Ton rôle est d'analyser les résultats bruts d'un scan de surface d'attaque
et de produire un rapport d'analyse de sécurité professionnel.

═══════════════════════════════════════════════════════════════
 IDENTITÉ ET POSTURE
═══════════════════════════════════════════════════════════════

- Tu raisonnes comme un pentester senior qui analyse la surface d'attaque
  EXTERNE d'une organisation.
- Tu ne te contentes JAMAIS de lister des faits bruts. Tu CORRÈLES, tu
  CONTEXTUALISES, tu RAISONNES sur l'impact opérationnel.
- Tu ne dis pas "Port 22 ouvert". Tu dis : "SSH exposé publiquement sur
  une IP qui héberge aussi un site WordPress — vecteur de brute force
  combiné credential stuffing possible si même mot de passe admin WP / SSH."
- Tu ne dis pas "WordPress détecté". Tu dis : "WordPress détecté sans
  version identifiée sur www.example.com — impossible de confirmer si les
  patches de sécurité sont à jour, surface d'attaque CMS classique
  (xmlrpc.php, wp-login.php, plugins vulnérables)."

═══════════════════════════════════════════════════════════════
 DONNÉES QUE TU REÇOIS
═══════════════════════════════════════════════════════════════

Tu reçois un bloc de texte structuré contenant :
- Le domaine cible et la date du scan
- Un résumé chiffré (sous-domaines, IPs, ports, technologies, endpoints)
- Les CPE matches (technologies avec identifiant CVE explorable)
- Le détail par sous-domaine :
  - IPs (avec indication CLOUDFLARE ou IP RÉELLE)
  - Enregistrements DNS (CNAME, MX, NS)
  - Ports ouverts par IP (avec service, version, bannière si disponible)
  - Services web (URL, code HTTP, redirection finale)
  - Technologies détectées (nom, version, confiance, source de détection, CPE)
  - IPs origine leakées (IPs réelles découvertes derrière un CDN)
  - Endpoints découverts par catégorie (sensitive, api, admin_panel, etc.)

═══════════════════════════════════════════════════════════════
 STRUCTURE EXACTE DU RAPPORT (6 NIVEAUX — RESPECTE CET ORDRE)
═══════════════════════════════════════════════════════════════

## N1 — Résumé exécutif de l'exposition

Objectif : donner en 8-12 lignes une vue macro compréhensible par un
décideur non technique.

Contenu obligatoire :
- Reprendre les chiffres clés du scan (sous-domaines, IPs, ports, techs)
- Attribuer un NIVEAU DE RISQUE GLOBAL : CRITIQUE / ÉLEVÉ / MODÉRÉ / FAIBLE
- Justifier ce niveau en 2-3 phrases qui résument les findings les plus
  graves (N2/N3)
- Mentionner les technologies sensibles détectées (panels admin, CMS,
  bases de données exposées)
- Si des IPs origine ont été leakées derrière Cloudflare, le mentionner
  explicitement comme risque de bypass CDN

Format :
```
🔴 NIVEAU DE RISQUE GLOBAL : [CRITIQUE/ÉLEVÉ/MODÉRÉ/FAIBLE]

[Chiffres clés en liste à puces]
[Justification en 2-3 phrases]
```

────────────────────────────────────────────────────────────────

## N2 — Corrélations dangereuses

Objectif : croiser les données entre elles pour identifier des COMBINAISONS
à haut risque. C'est ici que tu apportes ta valeur ajoutée d'analyste.

Règles :
- Chaque corrélation DOIT croiser AU MOINS 2 données différentes
  (ex: port + technologie, sous-domaine + endpoint, IP leakée + service)
- Chaque corrélation DOIT expliquer POURQUOI la combinaison est dangereuse
- Classe chaque corrélation : 🔴 CRITIQUE / 🟠 ÉLEVÉ / 🟡 MODÉRÉ

Types de corrélations à chercher systématiquement :
1. Panel admin exposé + technologie identifiée
   Ex: "cpanel.domain.com accessible (200) + port 2083 ouvert + LiteSpeed
   détecté → interface d'administration d'hébergement exposée publiquement
   avec contrôle total sur l'infrastructure"

2. IP réelle leakée + services sensibles sur cette IP
   Ex: "IP origine 1.2.3.4 leakée via header X-Backend-Server + ports
   SMTP (25, 587) ouverts sur cette IP → bypass Cloudflare possible,
   attaque directe sur le serveur mail sans protection DDoS"

3. Stack technologique vulnérable connue
   Ex: "WordPress + PHP 7.4 + CPE matchés → stack avec CVE connues,
   vérifier les versions exactes pour exploitation"

4. Vecteurs d'accès multiples sur la même IP
   Ex: "Port 21 (FTP) + port 22 (SSH) + sous-domaine ftp.domain.com →
   serveur de fichiers avec deux vecteurs d'accès simultanés, risque
   de credentials partagés"

5. API exposée sans protection apparente
   Ex: "editor-api.domain.com + Django détecté + /api/v1 retourne 200 +
   /swagger.json accessible → API backend exposée avec documentation
   publique, surface d'énumération complète"

6. Infrastructure mail complète exposée
   Ex: "Ports 25, 110, 143, 465, 587, 993, 995 tous ouverts → stack
   mail complète exposée, risque open relay, harvesting d'adresses,
   et vecteur de phishing si SPF/DKIM mal configurés"

7. Même IP partagée entre services critiques et non critiques
   Ex: "Le panel admin et le site public partagent la même IP 1.2.3.4 →
   compromission du site public = accès réseau au panel admin"

Format par corrélation :
```
🔴 [TITRE COURT]
  Données croisées : [liste des éléments corrélés]
  Analyse : [explication de pourquoi c'est dangereux]
  Impact : [conséquence concrète si exploité]
```

────────────────────────────────────────────────────────────────

## N3 — Chaînes d'attaque réalistes

Objectif : construire des SCÉNARIOS D'ATTAQUE MULTI-ÉTAPES complets,
comme un pentester qui planifie son attaque. Pas des vulnérabilités
isolées — des narratifs d'exploitation de bout en bout.

Règles :
- Chaque chaîne DOIT avoir entre 3 et 6 étapes concrètes
- Chaque étape DOIT décrire une MICRO-ACTION spécifique (pas vague)
- Chaque étape DOIT référencer des données réelles du scan
- Indique le niveau de difficulté : TRIVIAL / MODÉRÉ / AVANCÉ
- Indique les pré-requis (outils, accès nécessaires)

Exemple de niveau de détail attendu :
```
⛓ Scénario : Compromission via exposition Git
  Difficulté : TRIVIAL
  Pré-requis : git, curl

  1. RECONNAISSANCE : /.git/config accessible (HTTP 200) sur
     autoconfig.domain.com — le dépôt Git est exposé publiquement
  2. EXTRACTION : Utiliser git-dumper ou wget récursif pour
     télécharger l'intégralité du répertoire .git/
  3. RECONSTRUCTION : `git checkout .` pour reconstruire le code
     source complet de l'application
  4. RECHERCHE CREDENTIALS : grep -r "password\|secret\|api_key"
     dans le code source extrait — les fichiers .env, config.py,
     settings.json sont les cibles prioritaires
  5. PIVOT : Si credentials base de données trouvés → connexion
     directe si le port DB (3306/5432) est exposé (vérifier dans
     les ports ouverts du scan)
  6. ESCALADE : Accès DB = dump des utilisateurs, tokens de
     session, potentiel accès admin à l'application
```

Autre exemple :
```
⛓ Scénario : Pivot via serveur mail vulnérable
  Difficulté : MODÉRÉ
  Pré-requis : nmap scripts, searchsploit

  1. IDENTIFICATION : Exim 4.99.4 détecté via bannière sur port 25
  2. RECHERCHE CVE : searchsploit exim 4.99 — vérifier si version
     < 4.96 (CVE-2023-42115 à CVE-2023-42119, RCE pré-auth)
  3. EXPLOITATION : Si vulnérable, exploitation directe du service
     SMTP pour obtenir un shell sur le serveur mail
  4. PIVOT RÉSEAU : Depuis le serveur mail, scanner le réseau
     interne — les serveurs mail ont souvent accès aux réseaux
     internes pour la livraison locale
  5. EXFILTRATION : Accès aux boîtes mail = credentials, données
     sensibles, tokens de réinitialisation de mot de passe
```

Ne génère des chaînes QUE si les données du scan les supportent.
Si le scan ne révèle rien d'exploitable, dis-le clairement.

────────────────────────────────────────────────────────────────

## N4 — Observations complémentaires

Objectif : signaler les patterns SUSPECTS mais NON CONFIRMÉS qui
nécessitent une vérification manuelle. C'est la zone "à investiguer".

Types d'observations à chercher :

1. ANOMALIES DE COMPORTEMENT
   - Tous les endpoints fuzzing retournent 200 → "Serveur catch-all
     détecté, les résultats de fuzzing ne sont pas fiables pour ce
     service — vérification manuelle nécessaire"
   - Redirections en chaîne inhabituelles
   - Codes HTTP inattendus (403 sur des paths publics)

2. ISOLATION SUSPECTE
   - Sous-domaine sur une IP différente du reste → "Serveur isolé,
     potentiellement environnement staging/dev exposé en production"
   - Technologies différentes entre www et api → "Architectures
     mixtes, surface d'attaque hétérogène, potentiel shadow IT"

3. VERSIONS INCONNUES
   - WordPress détecté mais version non identifiée → "Impossible de
     confirmer si les patches sont à jour. Recommandation : vérifier
     manuellement via /wp-admin/about.php ou /feed/"
   - Service détecté sans bannière → "Service non identifié sur
     port X, vérification manuelle recommandée"

4. CONFIGURATIONS POTENTIELLEMENT DANGEREUSES
   - Redis/MongoDB/Elasticsearch exposé sur port standard → "Vérifier
     si une authentification est configurée"
   - FTP sans TLS (port 21 sans port 990) → "Transferts en clair
     possibles"

5. SURFACE D'ÉNUMÉRATION
   - /robots.txt accessible → "Peut révéler des paths cachés"
   - /sitemap.xml accessible → "Cartographie complète du site indexée"
   - /swagger.json ou /api-docs accessible → "Documentation API publique"

Format :
```
🔍 [OBSERVATION]
   Données : [ce qui a été détecté]
   Risque potentiel : [ce que ça pourrait impliquer]
   Action : [vérification manuelle recommandée]
```

────────────────────────────────────────────────────────────────

## N5 — Recommandations immédiates

Objectif : pour CHAQUE finding des niveaux N2, N3 et N4, donner une
recommandation concrète et actionnable.

Règles :
- Chaque recommandation DOIT référencer le finding correspondant
- Classe par matrice IMPACT × EFFORT :
  🔴 Impact élevé + Effort faible  = FAIRE IMMÉDIATEMENT
  🟠 Impact élevé + Effort modéré  = PLANIFIER CETTE SEMAINE
  🟡 Impact modéré + Effort faible = FAIRE QUAND POSSIBLE
  ⚪ Impact modéré + Effort élevé  = PLANIFIER AU BACKLOG

Format par recommandation :
```
🔴 [ACTION CONCRÈTE]
   Réf : [N2-x / N3-x / N4-x]
   Quoi : [description technique précise de ce qu'il faut faire]
   Comment : [commande, configuration, ou étape concrète]
   Vérification : [comment confirmer que c'est corrigé]
```

Exemples de recommandations concrètes :
- "Restreindre l'accès à /.git/ via règle nginx : location ~ /\\.git { deny all; }"
- "Placer le panel cPanel derrière un VPN ou restreindre par IP source"
- "Mettre à jour Exim vers >= 4.96.1 pour corriger CVE-2023-42115"
- "Configurer un firewall pour bloquer l'accès direct à l'IP origine,
  forcer le passage par Cloudflare"
- "Désactiver XML-RPC WordPress : ajouter dans .htaccess :
  <Files xmlrpc.php> Order Deny,Allow Deny from all </Files>"

────────────────────────────────────────────────────────────────

## N6 — Métriques de surface

Objectif : tableau récapitulatif des données brutes pour référence.

Contenu :
- Tableau des sous-domaines avec leur(s) IP(s) et statut Cloudflare
- Tableau des ports ouverts par IP (dédupliqué)
- Liste des technologies uniques détectées avec versions
- Liste des CPE matches
- Compteur d'endpoints par catégorie

Ce niveau est factuel, sans analyse. C'est l'annexe technique.

═══════════════════════════════════════════════════════════════
 RÈGLES ABSOLUES
═══════════════════════════════════════════════════════════════

1. NE JAMAIS inventer des données. Si un port n'est pas dans le scan,
   ne le mentionne pas. Si une version n'est pas détectée, dis
   "version inconnue", ne devine pas.

2. NE JAMAIS dire "Port X ouvert" sans contexte. Toujours expliquer
   POURQUOI c'est un problème dans CE contexte spécifique.

3. TOUJOURS croiser les données. Un port ouvert seul est un fait.
   Un port ouvert + une technologie + un endpoint = un finding.

4. TOUJOURS utiliser les noms exacts des sous-domaines, IPs, ports,
   technologies et endpoints du scan. Pas de généralisation.

5. Si le scan ne révèle rien de critique, dis-le honnêtement.
   Ne gonfle pas artificiellement la sévérité.

6. Écris en FRANÇAIS. Utilise le vocabulaire technique en anglais
   quand c'est le standard (CVE, CPE, RCE, SSRF, etc.).

7. Chaque niveau DOIT être présent dans le rapport, même si c'est
   pour dire "Aucune corrélation dangereuse identifiée".

8. Les chaînes d'attaque (N3) doivent être RÉALISTES. Ne propose
   pas d'exploiter une vulnérabilité si tu n'as pas la version
   exacte confirmée — dis plutôt "à vérifier".
"""


# ──────────────────────────────────────────────────────────────
# APPEL LLM
# ──────────────────────────────────────────────────────────────

def _appeler_openai(contexte: str) -> str:
    """Appelle un backend compatible OpenAI (OpenAI, OpenRouter, Ollama, etc.)."""
    import httpx

    url = f"{AI_BASE_URL}/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {AI_API_KEY}",
    }
    payload = {
        "model": AI_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    "Voici les résultats bruts du scan de surface d'attaque.\n"
                    "Analyse-les et produis le rapport structuré en 6 niveaux "
                    "comme décrit dans tes instructions.\n\n"
                    f"{contexte}"
                ),
            },
        ],
        "temperature": 0.3,
        "max_tokens": 8000,
    }

    response = httpx.post(url, json=payload, headers=headers, timeout=120.0)
    response.raise_for_status()
    data = response.json()
    return data["choices"][0]["message"]["content"]


def _appeler_anthropic(contexte: str) -> str:
    """Appelle l'API Anthropic (Claude)."""
    import httpx

    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "Content-Type": "application/json",
        "x-api-key": AI_API_KEY,
        "anthropic-version": "2023-06-01",
    }
    payload = {
        "model": AI_MODEL,
        "max_tokens": 8000,
        "system": SYSTEM_PROMPT,
        "messages": [
            {
                "role": "user",
                "content": (
                    "Voici les résultats bruts du scan de surface d'attaque.\n"
                    "Analyse-les et produis le rapport structuré en 6 niveaux "
                    "comme décrit dans tes instructions.\n\n"
                    f"{contexte}"
                ),
            },
        ],
        "temperature": 0.3,
    }

    response = httpx.post(url, json=payload, headers=headers, timeout=120.0)
    response.raise_for_status()
    data = response.json()
    return data["content"][0]["text"]


# ──────────────────────────────────────────────────────────────
# POINT D'ENTRÉE PUBLIC
# ──────────────────────────────────────────────────────────────

def generer_analyse_ia(scan: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Point d'entrée principal du module.

    Prend le dict complet d'un scan (tel que retourné par
    data_mapper.assembler_resultats) et retourne un dict contenant
    le rapport d'analyse IA.

    Args:
        scan : dict complet du scan avec subdomains, summary, cpe_matches, etc.

    Returns:
        dict {
            "report": str (markdown),
            "model": str,
            "provider": str,
            "duration": float (secondes),
        }
        ou None si l'IA n'est pas configurée.
    """
    if not AI_API_KEY:
        print("[ai_analyst] Pas de clé API configurée (AI_API_KEY), analyse IA ignorée.")
        return None

    print(f"[ai_analyst] Génération de l'analyse de sécurité via {AI_PROVIDER}/{AI_MODEL}...")
    debut = time.time()

    try:
        contexte = _extraire_contexte_scan(scan)

        # Log la taille du contexte pour debug
        print(f"[ai_analyst] Contexte extrait : {len(contexte)} caractères")

        if AI_PROVIDER == "anthropic":
            rapport = _appeler_anthropic(contexte)
        else:
            # openai, openrouter, ollama, ou tout provider compatible
            rapport = _appeler_openai(contexte)

        duree = round(time.time() - debut, 1)
        print(f"[ai_analyst] Analyse générée en {duree}s ({len(rapport)} caractères)")

        return {
            "report": rapport,
            "model": AI_MODEL,
            "provider": AI_PROVIDER,
            "duration": duree,
        }

    except Exception as e:
        duree = round(time.time() - debut, 1)
        print(f"[ai_analyst] Erreur après {duree}s : {type(e).__name__} — {e}")
        return {
            "report": f"Erreur lors de la génération du rapport IA : {e}",
            "model": AI_MODEL,
            "provider": AI_PROVIDER,
            "duration": duree,
            "error": str(e),
        }

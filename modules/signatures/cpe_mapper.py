"""
cpe_mapper.py — Mapping local technologie → CPE 2.3.

Transforme un couple (name, version) en URI CPE normalisée.
Approche retenue : mapping statique local (pas d'API NVD).

Avantages :
    - Rapide, hors ligne, pédagogique
    - Pas de dépendance Internet
    - Adapté au contexte du stage

Toutes les technologies ne produisent pas un CPE.
Exemple : Cloudflare, Google Analytics → cpe_status = "not_applicable"
"""

import re

# ──────────────────────────────────────────────────────────────
# TABLE DE CORRESPONDANCE
# Clé = nom canonique de la technologie (tel que dans web_signatures.py)
# Valeur = {part, vendor, product} pour construire le CPE 2.3
# ──────────────────────────────────────────────────────────────

CPE_MAPPING = {
    # Serveurs Web
    "nginx": {
        "part": "a",
        "vendor": "f5",
        "product": "nginx",
    },
    "Apache": {
        "part": "a",
        "vendor": "apache",
        "product": "http_server",
    },
    "Microsoft IIS": {
        "part": "a",
        "vendor": "microsoft",
        "product": "internet_information_services",
    },
    "LiteSpeed": {
        "part": "a",
        "vendor": "litespeedtech",
        "product": "litespeed_web_server",
    },
    "Caddy": {
        "part": "a",
        "vendor": "caddyserver",
        "product": "caddy",
    },

    # CMS
    "WordPress": {
        "part": "a",
        "vendor": "wordpress",
        "product": "wordpress",
    },
    "Drupal": {
        "part": "a",
        "vendor": "drupal",
        "product": "drupal",
    },
    "Joomla": {
        "part": "a",
        "vendor": "joomla",
        "product": "joomla\\!",
    },
    "Magento": {
        "part": "a",
        "vendor": "adobe",
        "product": "magento",
    },
    "Ghost": {
        "part": "a",
        "vendor": "ghost",
        "product": "ghost",
    },

    # Frameworks JS
    "React": {
        "part": "a",
        "vendor": "facebook",
        "product": "react",
    },
    "Angular": {
        "part": "a",
        "vendor": "google",
        "product": "angular",
    },
    "Vue.js": {
        "part": "a",
        "vendor": "vuejs",
        "product": "vue.js",
    },
    "Next.js": {
        "part": "a",
        "vendor": "vercel",
        "product": "next.js",
    },
    "Nuxt.js": {
        "part": "a",
        "vendor": "nuxtjs",
        "product": "nuxt.js",
    },
    "Gatsby": {
        "part": "a",
        "vendor": "gatsbyjs",
        "product": "gatsby",
    },

    # Frameworks backend
    "Django": {
        "part": "a",
        "vendor": "djangoproject",
        "product": "django",
    },
    "Laravel": {
        "part": "a",
        "vendor": "laravel",
        "product": "laravel",
    },
    "Ruby on Rails": {
        "part": "a",
        "vendor": "rubyonrails",
        "product": "rails",
    },
    "Express": {
        "part": "a",
        "vendor": "expressjs",
        "product": "express",
    },
    "Flask": {
        "part": "a",
        "vendor": "palletsprojects",
        "product": "flask",
    },
    "ASP.NET": {
        "part": "a",
        "vendor": "microsoft",
        "product": "asp.net",
    },
    "Spring": {
        "part": "a",
        "vendor": "vmware",
        "product": "spring_framework",
    },

    # Langages
    "PHP": {
        "part": "a",
        "vendor": "php",
        "product": "php",
    },
    "Java": {
        "part": "a",
        "vendor": "oracle",
        "product": "jdk",
    },

    # JS Libraries
    "jQuery": {
        "part": "a",
        "vendor": "jquery",
        "product": "jquery",
    },
    "Bootstrap": {
        "part": "a",
        "vendor": "getbootstrap",
        "product": "bootstrap",
    },
}

# Technologies qui ne produisent PAS de CPE pertinent
# (services SaaS, analytics, CDN gérés — pas de version exploitable)
CPE_NOT_APPLICABLE = {
    "Cloudflare",
    "AWS CloudFront",
    "Akamai",
    "Fastly",
    "Shopify",
    "Squarespace",
    "Wix",
    "Google Analytics",
    "Facebook Pixel",
    "Tailwind CSS",
    "Svelte",
}

# Longueur max d'une version extraite (anti-injection / stockage abusif)
# TODO(security) : les versions sont extraites de serveurs tiers non fiables
MAX_VERSION_LENGTH = 32


def _sanitize_cpe_component(component):
    """
    Échappe les caractères spéciaux dans un composant CPE 2.3.
    Seuls les caractères alphanumériques, '.', '-', '_' sont autorisés.
    """
    if not component:
        return "*"
    # Tronquer
    component = component[:MAX_VERSION_LENGTH]
    # Garder uniquement les caractères sûrs
    return re.sub(r"[^a-zA-Z0-9._\-]", "", component)


def generer_cpe(name, version=None):
    """
    Génère un CPE 2.3 URI à partir du nom et de la version d'une technologie.

    Retourne :
        dict {"uri": "cpe:2.3:...", "method": "local_mapping"}
        ou None si la technologie n'a pas de CPE pertinent.

    Exemples :
        generer_cpe("WordPress", "6.4.3")
        → {"uri": "cpe:2.3:a:wordpress:wordpress:6.4.3:*:*:*:*:*:*:*", ...}

        generer_cpe("Cloudflare")
        → None
    """
    # Pas de CPE pour cette technologie
    if name in CPE_NOT_APPLICABLE:
        return None

    mapping = CPE_MAPPING.get(name)
    if not mapping:
        return None

    part = mapping["part"]
    vendor = _sanitize_cpe_component(mapping["vendor"])
    product = _sanitize_cpe_component(mapping["product"])
    ver = _sanitize_cpe_component(version) if version else "*"

    uri = f"cpe:2.3:{part}:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"

    return {
        "uri": uri,
        "method": "local_mapping",
    }


def determiner_cpe_status(name, cpe_result):
    """
    Détermine le statut CPE d'une détection.

    Retourne :
        "matched"        — CPE généré avec succès
        "no_version"     — CPE possible mais version inconnue
        "not_applicable" — pas de CPE pertinent pour cette techno
        "unmapped"       — technologie non présente dans la table
    """
    if name in CPE_NOT_APPLICABLE:
        return "not_applicable"

    if name not in CPE_MAPPING:
        return "unmapped"

    if cpe_result is None:
        return "unmapped"

    if "*" in cpe_result["uri"].split(":")[5]:
        # Le champ version est un wildcard
        return "no_version"

    return "matched"

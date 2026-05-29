"""
web_signatures.py — Base de connaissances des signatures technologiques.

Ce fichier contient TOUTES les règles de détection. Le moteur (tech_detector.py)
se contente de les appliquer sans connaître les technologies individuellement.

Pour ajouter une nouvelle technologie :
    1. Ajouter une entrée dans WEB_SIGNATURES
    2. (Optionnel) Ajouter un mapping CPE dans cpe_mapper.py
    → Aucune modification du moteur nécessaire.

Types de détection disponibles :
    header_contains  — sous-chaîne dans la valeur d'un header HTTP
    header_regex     — regex sur la valeur d'un header (groupe 1 = version)
    meta_regex       — regex sur le content d'une balise <meta> (groupe 1 = version)
    html_contains    — sous-chaîne présente dans le HTML brut
    script_regex     — regex sur les attributs src des <script> (groupe 1 = version)
    cookie_contains  — nom de cookie dont la présence trahit la techno
"""

# ──────────────────────────────────────────────────────────────
# SIGNATURES
# ──────────────────────────────────────────────────────────────

WEB_SIGNATURES = [

    # ── Serveurs Web ──────────────────────────────────────────

    {
        "name": "nginx",
        "category": "server",
        "detection": {
            "header_regex": {"Server": r"nginx(?:/([\d.]+))?"},
        },
    },
    {
        "name": "Apache",
        "category": "server",
        "detection": {
            "header_regex": {"Server": r"Apache(?:/([\d.]+))?"},
        },
    },
    {
        "name": "Microsoft IIS",
        "category": "server",
        "detection": {
            "header_regex": {"Server": r"Microsoft-IIS/([\d.]+)"},
        },
    },
    {
        "name": "LiteSpeed",
        "category": "server",
        "detection": {
            "header_regex": {"Server": r"LiteSpeed(?:/([\d.]+))?"},
        },
    },
    {
        "name": "Caddy",
        "category": "server",
        "detection": {
            "header_regex": {"Server": r"Caddy(?:/([\d.]+))?"},
        },
    },

    # ── CMS ───────────────────────────────────────────────────

    {
        "name": "WordPress",
        "category": "cms",
        "detection": {
            "meta_regex": {"generator": r"WordPress\s*([\d.]+)?"},
            "html_contains": ["wp-content", "wp-includes", "wp-json"],
            "script_regex": [r"wp-includes/js/"],
            "cookie_contains": {"wordpress_logged_in": None},
            # Extrait la version depuis le lien canonical ou le readme
            "html_version_regex": [
                r'wp-includes/css/dashicons\.min\.css\?ver=([\d.]+)',
                r'wp-includes/js/wp-emoji-release\.min\.js\?ver=([\d.]+)',
                r'/wp-content/themes/[^/]+/style\.css\?ver=([\d.]+)',
            ],
        },
    },
    {
        "name": "Drupal",
        "category": "cms",
        "detection": {
            "meta_regex": {"generator": r"Drupal\s*([\d.]+)?"},
            "html_contains": ["sites/all", "sites/default", "drupal.js"],
            "header_contains": {"X-Generator": "Drupal"},
        },
    },
    {
        "name": "Joomla",
        "category": "cms",
        "detection": {
            "meta_regex": {"generator": r"Joomla[!]?\s*([\d.]+)?"},
            "html_contains": ["/media/jui/", "/components/com_"],
        },
    },
    {
        "name": "Magento",
        "category": "cms",
        "detection": {
            "html_contains": ["Mage.Cookies", "/skin/frontend/", "mage/cookies.js"],
            "cookie_contains": {"frontend": None},  # Cookie Magento courant
        },
    },
    {
        "name": "Shopify",
        "category": "cms",
        "detection": {
            "html_contains": ["cdn.shopify.com", "shopify.com/s/files"],
            "header_contains": {"X-ShopId": ""},
        },
    },
    {
        "name": "Squarespace",
        "category": "cms",
        "detection": {
            "html_contains": ["squarespace.com", "static.squarespace.com"],
        },
    },
    {
        "name": "Wix",
        "category": "cms",
        "detection": {
            "html_contains": ["wix.com", "static.wixstatic.com"],
            "meta_regex": {"generator": r"Wix\.com"},
        },
    },
    {
        "name": "Ghost",
        "category": "cms",
        "detection": {
            "meta_regex": {"generator": r"Ghost\s*([\d.]+)?"},
            "html_contains": ["ghost-"],
        },
    },

    # ── Frameworks JavaScript (frontend) ─────────────────────

    {
        "name": "React",
        "category": "js-framework",
        "detection": {
            # __NEXT_DATA__, _reactRootContainer: uppercase fragments → must match case-insensitively via html_lower
            "html_contains": ["__next_data__", "react-root", "_reactrootcontainer", "data-reactroot"],
            "script_regex": [r"react(?:\.production)?(?:\.min)?\.js"],
            # Extrait la version depuis les commentaires de bundle React
            "html_version_regex": [
                r'react@([\d.]+)',
                r'"react":\s*"([\d.]+)"',
            ],
        },
    },
    {
        "name": "Angular",
        "category": "js-framework",
        "detection": {
            "html_contains": ["ng-version", "ng-app", "_nghost", "_ngcontent"],
            "script_regex": [r"angular(?:\.min)?\.js"],
            # ng-version="X.Y.Z" est injecté directement dans le HTML par Angular
            "html_version_regex": [
                r'ng-version="([\d.]+)"',
                r'angular@([\d.]+)',
            ],
        },
    },
    {
        "name": "Vue.js",
        "category": "js-framework",
        "detection": {
            "html_contains": ["data-v-", "__vue"],
            "script_regex": [r"vue(?:\.runtime)?(?:\.min)?\.js"],
            "html_version_regex": [
                r'vue@([\d.]+)',
                r'"version":"([\d.]+)","_isVue"',
            ],
        },
    },
    {
        "name": "Next.js",
        "category": "js-framework",
        "detection": {
            # __NEXT_DATA__ est le nom réel dans le DOM — html_lower le convertit en minuscules
            # donc on met le fragment en minuscules directement pour la cohérence
            "html_contains": ["__next_data__", "_next/static"],
            "header_contains": {"X-Powered-By": "Next.js"},
            # La version est injectée dans le bloc __NEXT_DATA__ JSON ou dans les chemins de chunks
            "html_version_regex": [
                r'/_next/static/chunks/pages/_app-[a-f0-9]+\.js',  # présence seulement
                r'"nextjsVersion":"([\d.]+)"',
                r'/_next/static/([\d.]+)/',
            ],
        },
    },
    {
        "name": "Nuxt.js",
        "category": "js-framework",
        "detection": {
            # __nuxt__ est en minuscules dans le DOM
            "html_contains": ["__nuxt__", "_nuxt/"],
            "header_contains": {"X-Powered-By": "Nuxt"},
        },
    },
    {
        "name": "Svelte",
        "category": "js-framework",
        "detection": {
            "html_contains": ["svelte-", "__svelte"],
            "script_regex": [r"svelte(?:\.min)?\.js"],
        },
    },
    {
        "name": "Gatsby",
        "category": "js-framework",
        "detection": {
            "html_contains": ["___gatsby", "gatsby-"],
            "meta_regex": {"generator": r"Gatsby\s*([\d.]+)?"},
        },
    },

    # ── Frameworks Backend ────────────────────────────────────

    {
        "name": "Django",
        "category": "backend-framework",
        "detection": {
            "cookie_contains": {"csrftoken": None, "django_session": None},
            "header_contains": {"X-Frame-Options": "SAMEORIGIN"},
            # Django défini par défaut X-Frame-Options: SAMEORIGIN
            # mais c'est un signal faible — la confiance sera "low"
        },
    },
    {
        "name": "Laravel",
        "category": "backend-framework",
        "detection": {
            "cookie_contains": {"laravel_session": None, "XSRF-TOKEN": None},
            "header_contains": {"X-Powered-By": "Laravel"},
        },
    },
    {
        "name": "Ruby on Rails",
        "category": "backend-framework",
        "detection": {
            "cookie_contains": {"_rails_session": None, "rack.session": None},
            "header_contains": {"X-Powered-By": "Phusion Passenger"},
        },
    },
    {
        "name": "Express",
        "category": "backend-framework",
        "detection": {
            "header_contains": {"X-Powered-By": "Express"},
        },
    },
    {
        "name": "Flask",
        "category": "backend-framework",
        "detection": {
            "header_contains": {"Server": "Werkzeug"},
            "cookie_contains": {"session": None},
            # Signal faible — le cookie "session" est trop générique
        },
    },
    {
        "name": "ASP.NET",
        "category": "backend-framework",
        "detection": {
            "header_contains": {"X-Powered-By": "ASP.NET"},
            "header_regex": {"X-AspNet-Version": r"([\d.]+)"},
            "cookie_contains": {"ASP.NET_SessionId": None},
        },
    },
    {
        "name": "Spring",
        "category": "backend-framework",
        "detection": {
            "cookie_contains": {"JSESSIONID": None},
            "header_contains": {"X-Application-Context": ""},
        },
    },

    # ── Langages ──────────────────────────────────────────────

    {
        "name": "PHP",
        "category": "language",
        "detection": {
            "header_regex": {"X-Powered-By": r"PHP/([\d.]+)"},
            "cookie_contains": {"PHPSESSID": None},
        },
    },
    {
        "name": "Java",
        "category": "language",
        "detection": {
            "cookie_contains": {"JSESSIONID": None},
        },
    },

    # ── CDN / WAF ─────────────────────────────────────────────

    {
        "name": "Cloudflare",
        "category": "cdn",
        "detection": {
            "header_contains": {"Server": "cloudflare", "CF-RAY": ""},
        },
    },
    {
        "name": "AWS CloudFront",
        "category": "cdn",
        "detection": {
            "header_contains": {"X-Amz-Cf-Id": "", "Via": "CloudFront"},
        },
    },
    {
        "name": "Akamai",
        "category": "cdn",
        "detection": {
            "header_contains": {"X-Akamai-Transformed": ""},
            "header_regex": {"Server": r"AkamaiGHost"},
        },
    },
    {
        "name": "Fastly",
        "category": "cdn",
        "detection": {
            "header_contains": {"x-served-by": "cache-", "via": "varnish"},
        },
    },

    # ── Bibliothèques JS ────────────────────────────────────

    {
        "name": "jQuery",
        "category": "js-library",
        "detection": {
            # Le nom du fichier contient souvent la version: jquery-3.6.0.min.js
            "script_regex": [r"jquery[.-]([\d.]+)(?:\.min)?\.js"],
            "html_contains": ["jquery"],
            # jQuery 3.x injecte jQuery.fn.jquery dans window
            "html_version_regex": [
                r'jQuery v([\d.]+)',
                r'jquery:"([\d.]+)"',
                r'"jquery":"([\d.]+)"',
            ],
        },
    },
    {
        "name": "Bootstrap",
        "category": "js-library",
        "detection": {
            # Le nom du fichier contient souvent la version: bootstrap.5.3.0.min.js
            "script_regex": [r"bootstrap[.-]([\d.]+)(?:\.min)?\.js"],
            "html_contains": ["bootstrap"],
            "html_version_regex": [
                r'Bootstrap v([\d.]+)',
                r'"bootstrap":"([\d.]+)"',
            ],
        },
    },
    {
        "name": "Tailwind CSS",
        "category": "css-framework",
        "detection": {
            # Tailwind injecte des classes utilitaires très reconnaissables
            "html_contains": ["tailwindcss", "tailwind.min.css"],
        },
    },

    # ── Analytics / Tracking ──────────────────────────────────

    {
        "name": "Google Analytics",
        "category": "analytics",
        "detection": {
            # gtag( avec parenthèse : la recherche se fait sur html_lower donc "gtag(" devient "gtag("
            "html_contains": ["google-analytics.com", "gtag(", "googleanalyticsobject", "googletagmanager.com/gtag"],
            "script_regex": [r"googletagmanager\.com/gtag"],
        },
    },
    {
        "name": "Facebook Pixel",
        "category": "analytics",
        "detection": {
            "html_contains": ["fbq(", "connect.facebook.net/"],
            "script_regex": [r"connect\.facebook\.net/"],
        },
    },
]

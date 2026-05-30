from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import uvicorn
import os
import sys
import json
import time
import uuid
import asyncio
import threading

# Ajouter le répertoire racine au PYTHONPATH pour pouvoir importer les modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.runner import lancer_scan
from database.mongo_client import lister_scans, trouver_scan, supprimer_scan

app = FastAPI(
    title="Attack Surface Management API",
    description="API REST pour piloter le moteur de scan.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────────────────────
# Système de suivi en temps réel (SSE - Server-Sent Events)
# ──────────────────────────────────────────────────────────────
# Dictionnaire global qui stocke la progression de chaque scan actif
# Clé = task_id, Valeur = dict avec les infos de progression
active_scans = {}

class ScanRequest(BaseModel):
    target: str
    mode: str = "quick"  # "quick" = 1000 ports, "full" = 65535 ports


def run_scan_with_progress(task_id, domaine, mode="quick"):
    """
    Lance le pipeline complet tout en mettant à jour le dictionnaire
    active_scans à chaque étape pour que le front-end puisse suivre.
    """
    import time as t
    from config.settings import PORT_SCANNER_MODE
    from modules.data_mapper import assembler_resultats
    from modules.dns_resolver import resoudre_dns
    from modules.origin_tracker import is_cloudflare
    from modules.subdomain_discovery import trouver_sous_domaines
    from modules.tech_detector import detecter_technologies
    from modules.endpoint_discovery import lancer_decouverte_endpoints
    import platform, asyncio

    # Déterminer le nombre de ports selon le mode
    max_ports = 65535 if mode == "full" else 1000

    def scanner_ports_local(sous_domaines_resolus):
        if PORT_SCANNER_MODE == "async":
            from modules.SCANNER_VARIANT.port_scanner_async import scanner_ports as impl
        elif PORT_SCANNER_MODE == "process":
            from modules.SCANNER_VARIANT.port_scanner_multiprocess import scanner_ports as impl
        elif platform.system() == "Windows":
            from modules.SCANNER_VARIANT.port_scanner import scanner_ports as impl
        else:
            from modules.SCANNER_VARIANT.port_scanner_multiprocess import scanner_ports as impl
        return impl(sous_domaines_resolus, max_ports)

    steps = [
        "Découverte des sous-domaines",
        "Résolution DNS",
        "Scan des ports",
        "Détection des technologies",
        "Découverte des endpoints",
        "Assemblage et sauvegarde"
    ]

    progress = active_scans[task_id]
    progress["target"] = domaine
    progress["status"] = "running"
    progress["total_steps"] = len(steps)

    debut_total = t.time()

    try:
        # Étape 1 : Sous-domaines
        progress["current_step"] = 1
        progress["step_name"] = steps[0]
        debut = t.time()
        sous_domaines = trouver_sous_domaines(domaine)
        if not sous_domaines:
            progress["status"] = "error"
            progress["error"] = "Aucun sous-domaine trouvé"
            return
        progress["step_duration"] = round(t.time() - debut, 1)
        progress["details"] = f"{len(sous_domaines)} sous-domaines"
        print(
            f"[PERF][pipeline] step=subdomains duree={progress['step_duration']}s "
            f"count={len(sous_domaines)}"
        )

        # Étape 2 : DNS
        progress["current_step"] = 2
        progress["step_name"] = steps[1]
        progress["details"] = ""
        debut = t.time()
        sous_domaines_resolus = resoudre_dns(sous_domaines)
        if not sous_domaines_resolus:
            progress["status"] = "error"
            progress["error"] = "Aucun sous-domaine résolu"
            return
        progress["step_duration"] = round(t.time() - debut, 1)
        print(
            f"[PERF][pipeline] step=dns duree={progress['step_duration']}s "
            f"count={len(sous_domaines_resolus)}"
        )
        progress["details"] = f"{len(sous_domaines_resolus)} résolus"

        # Étape 3 : Ports
        progress["current_step"] = 3
        progress["step_name"] = steps[2]
        mode_label = "Top-1000 Nmap" if max_ports == 1000 else f"1-{max_ports}"
        progress["details"] = f"Mode : {mode_label} ({max_ports} ports par IP)..."
        debut = t.time()
        sous_domaines_scannes = scanner_ports_local(sous_domaines_resolus)
        progress["step_duration"] = round(t.time() - debut, 1)
        total_ports = sum(
            len(ports) for sd in sous_domaines_scannes
            for ports in sd.get("ports_par_ip", {}).values()
        )
        progress["details"] = f"{total_ports} ports ouverts trouvés"
        print(
            f"[PERF][pipeline] step=ports duree={progress['step_duration']}s "
            f"open_ports={total_ports}"
        )

        # ── Catégorisation Cloudflare via ip_meta ──
        cf_count = 0
        real_count = 0
        for entree in sous_domaines_scannes:
            entree.setdefault("ip_meta", {})
            for ip in entree["ips"]:
                is_cf = is_cloudflare(ip)
                entree["ip_meta"][ip] = {"is_cloudflare": is_cf}
                if is_cf: cf_count += 1
                else: real_count += 1
        print(f"[pipeline] IPs catégorisées : {cf_count} Cloudflare, {real_count} réelles")

        # Étape 4 : Technologies
        progress["current_step"] = 4
        progress["step_name"] = steps[3]
        progress["details"] = ""
        debut = t.time()
        sous_domaines_enrichis = asyncio.run(
            detecter_technologies(sous_domaines_scannes)
        )
        progress["step_duration"] = round(t.time() - debut, 1)
        total_services = sum(
            len(sd.get("services_web", [])) for sd in sous_domaines_enrichis
        )
        total_technologies = len({
            tech
            for sd in sous_domaines_enrichis
            for service in sd.get("services_web", [])
            for tech in service.get("technologies", [])
        })
        print(
            f"[PERF][pipeline] step=technologies duree={progress['step_duration']}s "
            f"services={total_services} technologies={total_technologies}"
        )

        # ── Agrégation des IPs origine leakées via headers HTTP ──
        leaked_ips = set()
        all_dns_ips = {ip for sd in sous_domaines_scannes for ip in sd.get("ips", [])}
        for sd in sous_domaines_enrichis:
            for service in sd.get("services_web", []):
                for ip in service.get("leaked_origin_ips", []):
                    if ip not in all_dns_ips:
                        leaked_ips.add(ip)

        if leaked_ips:
            print(f"[pipeline] {len(leaked_ips)} IP(s) origine leakée(s) : {leaked_ips}")
            leaked_entries = [
                {"subdomain": f"leaked-origin/{ip}", "ips": [ip],
                 "mx": [], "ns": [], "cname": None}
                for ip in leaked_ips
            ]
            try:
                leaked_scannes = scanner_ports_local(leaked_entries)
                for entry in leaked_scannes:
                    entry["tags"] = ["ORIGIN_SERVER"]
                sous_domaines_enrichis = sous_domaines_enrichis + leaked_scannes
                print(f"[pipeline] Scan leaked IPs terminé ({len(leaked_scannes)} entrées)")
            except Exception as e:
                print(f"[pipeline] Scan leaked IPs non bloquant : {e}")
        else:
            print("[pipeline] Aucune IP origine leakée détectée")

        # Étape 5 : Endpoints
        progress["current_step"] = 5
        progress["step_name"] = steps[4]
        progress["details"] = ""
        debut = t.time()
        sous_domaines_fuzzes = lancer_decouverte_endpoints(sous_domaines_enrichis)
        progress["step_duration"] = round(t.time() - debut, 1)
        total_endpoints = sum(
            len(service.get("endpoints", []))
            for sd in sous_domaines_fuzzes
            for service in sd.get("services_web", [])
        )
        print(
            f"[PERF][pipeline] step=endpoints duree={progress['step_duration']}s "
            f"endpoints={total_endpoints}"
        )

        # Étape 6 : Assemblage
        progress["current_step"] = 6
        progress["step_name"] = steps[5]
        progress["details"] = ""
        debut = t.time()
        resultat_final = assembler_resultats(domaine, sous_domaines_fuzzes)

        duree_totale = round(t.time() - debut_total, 1)
        resultat_final["summary"]["total_duration"] = duree_totale
        resultat_final["mode"] = mode

        # Sauvegarde MongoDB
        try:
            from database.mongo_client import sauvegarder_scan
            mongo_id = sauvegarder_scan(resultat_final)
        except Exception:
            pass

        progress["step_duration"] = round(t.time() - debut, 1)
        print(
            f"[PERF][pipeline] step=assemble_save duree={progress['step_duration']}s "
            f"total={duree_totale}s"
        )
        progress["status"] = "done"
        progress["total_duration"] = duree_totale
        progress["scan_id"] = resultat_final.get("scan_id")
        progress["summary"] = resultat_final.get("summary", {})

    except Exception as e:
        progress["status"] = "error"
        progress["error"] = str(e)


@app.get("/api")
def read_root():
    return {"status": "online", "message": "ASM API is running."}


@app.post("/api/scans")
def start_scan(request: ScanRequest):
    domaine = request.target.strip().lower()
    mode = request.mode if request.mode in ("quick", "full") else "quick"
    if not domaine:
        raise HTTPException(status_code=400, detail="Le domaine ne peut pas être vide.")

    task_id = str(uuid.uuid4())[:8]
    active_scans[task_id] = {
        "task_id": task_id,
        "target": domaine,
        "mode": mode,
        "status": "starting",
        "current_step": 0,
        "total_steps": 6,
        "step_name": "Initialisation...",
        "details": "",
        "step_duration": 0,
    }

    thread = threading.Thread(
        target=run_scan_with_progress,
        args=(task_id, domaine, mode),
        daemon=True
    )
    thread.start()

    return {"status": "accepted", "task_id": task_id, "target": domaine, "mode": mode}


@app.get("/api/scans/progress/{task_id}")
def get_progress(task_id: str):
    """Retourne la progression instantanée d'un scan actif."""
    if task_id not in active_scans:
        raise HTTPException(status_code=404, detail="Tâche introuvable.")
    return active_scans[task_id]


@app.get("/api/scans/stream/{task_id}")
async def stream_progress(task_id: str):
    """
    Endpoint SSE (Server-Sent Events).
    Le front-end se connecte ici et reçoit des mises à jour en temps réel.
    """
    if task_id not in active_scans:
        raise HTTPException(status_code=404, detail="Tâche introuvable.")

    async def event_generator():
        while True:
            if task_id in active_scans:
                data = json.dumps(active_scans[task_id], ensure_ascii=False)
                yield f"data: {data}\n\n"
                if active_scans[task_id]["status"] in ("done", "error"):
                    break
            await asyncio.sleep(0.5)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/scans")
def get_all_scans():
    scans = lister_scans()
    return {"status": "success", "count": len(scans), "data": scans}


def enrichir_ip_meta(scan):
    """Recalcule ip_meta pour les scans historiques sans ce champ."""
    from modules.origin_tracker import is_cloudflare

    for sd in scan.get("subdomains", []):
        sd["ip_meta"] = {
            ip: {"is_cloudflare": is_cloudflare(ip)}
            for ip in sd.get("ips", [])
        }
    return scan


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    scan = trouver_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} introuvable.")
    return {"status": "success", "data": enrichir_ip_meta(scan)}


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str):
    success = supprimer_scan(scan_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} introuvable.")
    return {"status": "success", "message": f"Scan {scan_id} supprimé."}


# Montage des fichiers statiques (après les routes /api)
frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")

if __name__ == "__main__":
    print("\n=======================================================")
    print("  ASM Recon — Serveur API sur http://localhost:8000")
    print("=======================================================\n")
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)

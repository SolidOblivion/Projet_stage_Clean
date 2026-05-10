const API = '/api/scans';

// ── DOM ──
const scanForm       = document.getElementById('scan-form');
const targetInput    = document.getElementById('target-input');
const btnScan        = document.getElementById('btn-scan');
const tableBody      = document.getElementById('table-body');
const btnRefresh     = document.getElementById('btn-refresh');
const refreshIcon    = document.getElementById('refresh-icon');
const statsRow       = document.getElementById('stats-row');

const progressPanel  = document.getElementById('progress-panel');
const progressTarget = document.getElementById('progress-target');
const progressBadge  = document.getElementById('progress-step-badge');
const progressBar    = document.getElementById('progress-bar');
const progressName   = document.getElementById('progress-step-name');
const progressDetail = document.getElementById('progress-step-detail');
const progressSteps  = document.getElementById('progress-steps');

const modalOverlay   = document.getElementById('modal-overlay');
const modalClose     = document.getElementById('modal-close');
const modalTitle     = document.getElementById('modal-title');
const modalBody      = document.getElementById('modal-body');

// ── Init ──
document.addEventListener('DOMContentLoaded', fetchScans);

// ── Refresh ──
btnRefresh.addEventListener('click', () => {
    refreshIcon.classList.add('spin');
    fetchScans().finally(() => setTimeout(() => refreshIcon.classList.remove('spin'), 500));
});

// ── Submit Scan ──
scanForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const target = targetInput.value.trim();
    if (!target) return;
    const mode = document.querySelector('input[name="scan-mode"]:checked')?.value || 'quick';

    btnScan.disabled = true;
    btnScan.innerHTML = '<i class="ph ph-spinner-gap spin"></i> Envoi...';

    try {
        const res = await fetch(API, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, mode })
        });
        const data = await res.json();
        if (res.ok) {
            targetInput.value = '';
            startLiveTracking(data.task_id, data.target, mode);
        }
    } catch (err) {
        console.error(err);
    } finally {
        btnScan.disabled = false;
        btnScan.innerHTML = '<i class="ph ph-radar"></i><span>Lancer le scan</span>';
    }
});

// ── SSE Live Tracking ──
function startLiveTracking(taskId, target, mode) {
    const modeLabel = mode === 'full' ? '🔍 Complet (65 535 ports)' : '⚡ Rapide (1 000 ports)';
    progressPanel.classList.remove('hidden', 'done', 'error');
    progressTarget.textContent = `${target} — ${modeLabel}`;
    progressBar.style.width = '0%';
    progressBadge.textContent = 'Étape 0/6';
    progressName.textContent = 'Connexion...';
    progressDetail.textContent = '';

    progressSteps.innerHTML = '';
    for (let i = 0; i < 6; i++) {
        const d = document.createElement('div');
        d.className = 'step-dot';
        d.id = `dot-${i}`;
        progressSteps.appendChild(d);
    }

    const evtSource = new EventSource(`/api/scans/stream/${taskId}`);
    evtSource.onmessage = (event) => {
        const d = JSON.parse(event.data);
        const step = d.current_step || 0;
        const total = d.total_steps || 6;
        const pct = Math.round((step / total) * 100);

        progressBar.style.width = pct + '%';
        progressBadge.textContent = `Étape ${step}/${total}`;
        progressName.textContent = d.step_name || '';
        progressDetail.textContent = d.details || '';

        for (let i = 0; i < total; i++) {
            const dot = document.getElementById(`dot-${i}`);
            if (!dot) continue;
            dot.className = 'step-dot';
            if (i < step - 1) dot.classList.add('done');
            else if (i === step - 1) dot.classList.add('active');
        }

        if (d.status === 'done') {
            evtSource.close();
            progressPanel.classList.add('done');
            progressBar.style.width = '100%';
            progressName.textContent = `✓ Terminé en ${d.total_duration}s`;
            progressBadge.textContent = '✓ Terminé';
            progressDetail.textContent = '';
            for (let i = 0; i < total; i++) {
                const dot = document.getElementById(`dot-${i}`);
                if (dot) dot.className = 'step-dot done';
            }
            fetchScans();
            setTimeout(() => progressPanel.classList.add('hidden'), 10000);
        }
        if (d.status === 'error') {
            evtSource.close();
            progressPanel.classList.add('error');
            progressName.textContent = `✗ Erreur : ${d.error || 'Inconnue'}`;
            progressBadge.textContent = '✗ Erreur';
        }
    };
    evtSource.onerror = () => evtSource.close();
}

// ── Fetch All Scans ──
async function fetchScans() {
    try {
        const res = await fetch(API);
        const data = await res.json();
        if (data.status === 'success') {
            renderTable(data.data);
            renderStats(data.data);
        }
    } catch {
        tableBody.innerHTML = '<tr><td colspan="7" class="empty-td">Erreur de connexion au serveur</td></tr>';
    }
}

// ── Stats (Dernier scan) ──
function renderStats(scans) {
    if (!scans || scans.length === 0) {
        statsRow.innerHTML = '';
        return;
    }
    // Le dernier scan est le premier dans la liste (tri par date décroissante depuis MongoDB)
    const last = scans[0];
    const s = last.summary || {};
    const mode = last.mode || 'quick';
    const modeLabel = mode === 'full' ? '🔍 65 535 ports' : '⚡ 1 000 ports';

    statsRow.innerHTML = `
        <div class="stats-title" style="grid-column:1/-1; margin-bottom:-8px">
            Dernier scan : <strong>${last.target}</strong> — ${new Date(last.scan_date).toLocaleString('fr-FR')}
        </div>
        <div class="stat-card">
            <div class="stat-icon purple"><i class="ph ph-globe-hemisphere-east"></i></div>
            <div class="stat-body">
                <span class="stat-number">${s.total_subdomains || 0}</span>
                <span class="stat-label">Sous-domaines</span>
            </div>
        </div>
        <div class="stat-card">
            <div class="stat-icon blue"><i class="ph ph-network"></i></div>
            <div class="stat-body">
                <span class="stat-number">${s.total_ips || 0}</span>
                <span class="stat-label">IPs uniques</span>
            </div>
        </div>
        <div class="stat-card">
            <div class="stat-icon green"><i class="ph ph-plugs-connected"></i></div>
            <div class="stat-body">
                <span class="stat-number">${s.total_open_ports || 0}</span>
                <span class="stat-label">Ports ouverts</span>
            </div>
        </div>
        <div class="stat-card">
            <div class="stat-icon orange"><i class="ph ph-cpu"></i></div>
            <div class="stat-body">
                <span class="stat-number">${s.total_technologies || 0}</span>
                <span class="stat-label">Technologies</span>
            </div>
        </div>
        <div class="stat-card accent">
            <div class="stat-icon white"><i class="ph ph-path"></i></div>
            <div class="stat-body">
                <span class="stat-number">${s.total_endpoints || 0}</span>
                <span class="stat-label">${modeLabel}</span>
            </div>
        </div>`;
}

// ── Render Table ──
function renderTable(scans) {
    if (!scans.length) {
        tableBody.innerHTML = '<tr><td colspan="7" class="empty-td">Aucun scan dans l\'historique</td></tr>';
        return;
    }
    tableBody.innerHTML = '';
    scans.forEach(scan => {
        const d = new Date(scan.scan_date).toLocaleString('fr-FR', {
            day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit'
        });
        const s = scan.summary || {};
        const mode = scan.mode || 'quick';
        const modePill = mode === 'full'
            ? '<span class="pill p">Complet</span>'
            : '<span class="pill gray">Rapide</span>';

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><div class="target-name"><span class="target-dot"></span>${scan.target}</div></td>
            <td style="color:var(--text2);font-size:12px">${d} ${s.total_duration ? `<br><span style="color:var(--text3)">${s.total_duration}s</span>` : ''}</td>
            <td>${modePill}</td>
            <td><span class="pill b">${s.total_subdomains || 0}</span></td>
            <td><span class="pill g">${s.total_open_ports || 0}</span></td>
            <td><span class="pill o">${s.total_technologies || 0}</span></td>
            <td>
                <div class="actions">
                    <button class="btn-sm" onclick="openModal('${scan.scan_id}')">
                        <i class="ph ph-eye"></i> Voir le rapport
                    </button>
                    <button class="btn-sm danger" onclick="deleteScan('${scan.scan_id}', this)">
                        <i class="ph ph-trash"></i> Supprimer
                    </button>
                </div>
            </td>`;
        tableBody.appendChild(tr);
    });
}

// ── Delete ──
async function deleteScan(id, btn) {
    if (!confirm('Supprimer ce scan de l\'historique ?')) return;
    btn.disabled = true;
    btn.innerHTML = '<i class="ph ph-spinner-gap spin"></i>';
    try {
        const res = await fetch(`${API}/${id}`, { method: 'DELETE' });
        if (res.ok) {
            fetchScans();
        } else {
            btn.disabled = false;
            btn.innerHTML = '<i class="ph ph-trash"></i> Supprimer';
        }
    } catch {
        btn.disabled = false;
        btn.innerHTML = '<i class="ph ph-trash"></i> Supprimer';
    }
}

// ── Modal ──
modalClose.addEventListener('click', () => modalOverlay.classList.remove('open'));
modalOverlay.addEventListener('click', e => { if (e.target === modalOverlay) modalOverlay.classList.remove('open'); });

async function openModal(id) {
    modalOverlay.classList.add('open');
    modalTitle.textContent = 'Chargement du rapport...';
    modalBody.innerHTML = '<div style="text-align:center;padding:40px;color:var(--text3)"><i class="ph ph-spinner-gap spin" style="font-size:28px"></i></div>';

    try {
        const res = await fetch(`${API}/${id}`);
        const result = await res.json();
        if (result.status === 'success') renderModalContent(result.data);
    } catch {
        modalBody.innerHTML = '<p style="color:var(--red)">Erreur de chargement du rapport.</p>';
    }
}

function renderModalContent(data) {
    const dur = data.summary?.total_duration 
        ? `<span style="font-size:13px; font-weight:normal; color:var(--text3); margin-left:8px;">(Durée : ${data.summary.total_duration}s)</span>` 
        : '';
    modalTitle.innerHTML = `Rapport — ${data.target}${dur}`;

    if (!data.subdomains || !data.subdomains.length) {
        modalBody.innerHTML = '<p class="no-data">Aucun résultat disponible pour ce scan.</p>';
        return;
    }

    modalBody.innerHTML = '';

    data.subdomains.forEach(sd => {
        // ── Collecter tous les ports de toutes les IPs
        let allPorts = [];
        for (const [ip, portList] of Object.entries(sd.ports_par_ip || {})) {
            portList.forEach(p => {
                allPorts.push({ ip, port: p.port, service: p.service, proto: p.protocole });
            });
        }
        allPorts.sort((a, b) => a.port - b.port);

        // ── Infos DNS
        const dns = sd.dns || {};
        const mx = dns.mx || [];
        const ns = dns.ns || [];
        const cname = dns.cname;

        // ── Construire la carte
        const card = document.createElement('div');
        card.className = 'sd-card';

        let portsHTML = allPorts.length
            ? allPorts.map(p => `<span class="tag-port">${p.port}/${p.proto} — ${p.service} <small style="opacity:.7">[${p.ip}]</small></span>`).join('')
            : '<span class="no-data">Aucun port ouvert détecté</span>';

        let dnsHTML = '';
        if (ns.length)  dnsHTML += `<div class="dns-row">NS : ${ns.join(', ')}</div>`;
        if (mx.length)  dnsHTML += `<div class="dns-row">MX : ${mx.join(', ')}</div>`;
        if (cname)      dnsHTML += `<div class="dns-row">CNAME : ${cname}</div>`;
        if (!dnsHTML)   dnsHTML = '<span class="no-data">Aucun enregistrement DNS spécial</span>';

        // ── Services Web
        let webHTML = '';
        if (sd.services_web && sd.services_web.length) {
            sd.services_web.forEach(sw => {
                const statusClass = sw.status_code === 200 ? 's200'
                    : (sw.status_code === 403 ? 's403' : 's301');

                let techsHTML = sw.technologies && sw.technologies.length
                    ? sw.technologies.map(t => `<span class="tag-tech">${t}</span>`).join('')
                    : '<span class="no-data">Aucune technologie détectée</span>';

                let epHTML = '';
                if (sw.endpoints && sw.endpoints.length) {
                    epHTML = `
                        <div class="info-row">
                            <span class="info-label">Endpoints</span>
                            <ul class="ep-list">
                                ${sw.endpoints.map(ep =>
                                    `<li><span>${ep.path}</span><span class="c${ep.status_code}">${ep.status_code}</span></li>`
                                ).join('')}
                            </ul>
                        </div>`;
                }

                webHTML += `
                    <div class="web-block">
                        <div class="web-block-header">
                            <a href="${sw.url}" target="_blank">${sw.url}</a>
                            <span class="status-badge ${statusClass}">${sw.status_code}</span>
                            ${sw.final_url && sw.final_url !== sw.url
                                ? `<span style="font-size:11px;color:var(--text3)">→ ${sw.final_url}</span>`
                                : ''}
                        </div>
                        <div class="web-block-body">
                            <div class="info-row">
                                <span class="info-label">Technologies</span>
                                <div class="tags">${techsHTML}</div>
                            </div>
                            ${epHTML}
                        </div>
                    </div>`;
            });
        } else {
            webHTML = '<span class="no-data">Aucun service web détecté sur cette cible</span>';
        }

        card.innerHTML = `
            <div class="sd-header">
                <h4><i class="ph ph-link"></i> ${sd.subdomain}</h4>
                <span class="sd-ips">${(sd.ips || []).join(' • ')}</span>
            </div>
            <div class="sd-body">
                <div class="info-row">
                    <span class="info-label">Ports ouverts</span>
                    <div class="tags">${portsHTML}</div>
                </div>
                <div class="info-row">
                    <span class="info-label">DNS</span>
                    <div>${dnsHTML}</div>
                </div>
                <div class="info-row">
                    <span class="info-label">Services web</span>
                    <div style="flex:1;display:flex;flex-direction:column;gap:8px">${webHTML}</div>
                </div>
            </div>`;

        modalBody.appendChild(card);
    });
}

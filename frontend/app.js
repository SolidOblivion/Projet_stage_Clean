const API = '/api/scans';

// ── DOM ──
const scanForm       = document.getElementById('scan-form');
const targetInput    = document.getElementById('target-input');
const btnScan        = document.getElementById('btn-scan');
const tableBody      = document.getElementById('table-body');
const btnRefresh     = document.getElementById('btn-refresh');
const refreshIcon    = document.getElementById('refresh-icon');
const statsRow       = document.getElementById('stats-row');
const searchInput    = document.getElementById('search-input');

let cachedScans = [];

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
document.addEventListener('DOMContentLoaded', () => {
    fetchScans();
    searchInput.addEventListener('input', () => {
        const query = searchInput.value.trim().toLowerCase();
        if (!query) {
            renderTable(cachedScans);
            return;
        }
        const filtered = cachedScans.filter(s => (s.target || '').toLowerCase().includes(query));
        renderTable(filtered, true);
    });
});

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
    progressBadge.textContent = 'Étape 0/8';
    progressName.textContent = 'Connexion...';
    progressDetail.textContent = '';

    // Les dots sont créés dynamiquement selon total_steps du serveur
    progressSteps.innerHTML = '';
    let dotsCreated = 0;

    const evtSource = new EventSource(`/api/scans/stream/${taskId}`);
    evtSource.onmessage = (event) => {
        const d = JSON.parse(event.data);
        const step = d.current_step || 0;
        const total = d.total_steps || 8;
        const pct = Math.round((step / total) * 100);

        // Créer les dots une seule fois quand on connaît le total
        if (dotsCreated !== total) {
            progressSteps.innerHTML = '';
            for (let i = 0; i < total; i++) {
                const dot = document.createElement('div');
                dot.className = 'step-dot';
                dot.id = `dot-${i}`;
                progressSteps.appendChild(dot);
            }
            dotsCreated = total;
        }

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
        tableBody.innerHTML = '<tr><td colspan="9" class="empty-td">Erreur de connexion au serveur</td></tr>';
    }
}

// ── Stats (Dernier scan) ──
function renderStats(scans) {
    if (!scans || scans.length === 0) {
        statsRow.innerHTML = '';
        return;
    }
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
function renderTable(scans, isFiltered = false) {
    if (!isFiltered) cachedScans = scans;
    if (!scans.length) {
        tableBody.innerHTML = isFiltered
            ? '<tr><td colspan="9" class="no-results-row">Aucun résultat trouvé.</td></tr>'
            : '<tr><td colspan="9" class="empty-td">Aucun scan dans l\'historique</td></tr>';
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
            <td><span class="pill ip">${s.total_ips || 0}</span></td>
            <td><span class="pill g">${s.total_open_ports || 0}</span></td>
            <td><span class="pill o">${s.total_technologies || 0}</span></td>
            <td><span class="pill ep">${s.total_endpoints || 0}</span></td>
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

// ── Lightweight Markdown → HTML ──
function markdownToHtml(md) {
    if (!md) return '';
    let html = md
        // Escape HTML entities first
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        // Code blocks (``` ... ```)
        .replace(/```([\s\S]*?)```/g, '<pre class="ai-code">$1</pre>')
        // Inline code
        .replace(/`([^`]+)`/g, '<code class="ai-inline-code">$1</code>')
        // Headers
        .replace(/^### (.+)$/gm, '<h5 class="ai-h3">$1</h5>')
        .replace(/^## (.+)$/gm, '<h4 class="ai-h2">$1</h4>')
        .replace(/^# (.+)$/gm, '<h3 class="ai-h1">$1</h3>')
        // Bold
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        // Italic
        .replace(/\*(.+?)\*/g, '<em>$1</em>')
        // Severity emojis → styled badges
        .replace(/🔴\s*(CRITIQUE|NIVEAU DE RISQUE GLOBAL\s*:\s*CRITIQUE)/g, '<span class="ai-sev ai-sev-crit">🔴 $1</span>')
        .replace(/🔴/g, '<span class="ai-sev ai-sev-crit">🔴</span>')
        .replace(/🟠/g, '<span class="ai-sev ai-sev-high">🟠</span>')
        .replace(/🟡/g, '<span class="ai-sev ai-sev-med">🟡</span>')
        .replace(/⚪/g, '<span class="ai-sev ai-sev-low">⚪</span>')
        .replace(/🔍/g, '<span class="ai-sev ai-sev-info">🔍</span>')
        .replace(/⛓/g, '<span class="ai-sev ai-sev-chain">⛓</span>')
        // Horizontal rules
        .replace(/^-{3,}$/gm, '<hr class="ai-hr">')
        .replace(/^─{3,}$/gm, '<hr class="ai-hr">')
        // Bullet lists
        .replace(/^\s*[-*]\s+(.+)$/gm, '<li>$1</li>')
        // Numbered lists
        .replace(/^\s*\d+\.\s+(.+)$/gm, '<li class="ai-ol">$1</li>')
        // Paragraphs (double newline)
        .replace(/\n\n/g, '</p><p>')
        // Single newlines within paragraphs
        .replace(/\n/g, '<br>');

    // Wrap consecutive <li> in <ul>
    html = html.replace(/(<li>.*?<\/li>(?:<br>)?)+/g, (match) => {
        return '<ul class="ai-list">' + match.replace(/<br>/g, '') + '</ul>';
    });
    html = html.replace(/(<li class="ai-ol">.*?<\/li>(?:<br>)?)+/g, (match) => {
        return '<ol class="ai-list">' + match.replace(/<br>/g, '').replace(/ class="ai-ol"/g, '') + '</ol>';
    });

    return '<p>' + html + '</p>';
}

// ── AI Analysis Section ──
function renderAiAnalysis(data, container) {
    const scanId = data.scan_id;
    const analysis = data.ai_analysis;

    const aiBlock = document.createElement('div');
    aiBlock.className = 'ai-analysis-block';
    aiBlock.id = 'ai-analysis-block';

    // Header
    const aiHeader = document.createElement('div');
    aiHeader.className = 'ai-analysis-header';

    const aiTitle = document.createElement('div');
    aiTitle.className = 'ai-analysis-title';
    const brainIcon = document.createElement('i');
    brainIcon.className = 'ph ph-brain';
    aiTitle.appendChild(brainIcon);
    aiTitle.appendChild(document.createTextNode(' Analyse de sécurité IA'));
    aiHeader.appendChild(aiTitle);

    if (analysis && analysis.report && !analysis.error) {
        // Analyse disponible — afficher le rapport
        const metaSpan = document.createElement('span');
        metaSpan.className = 'ai-analysis-meta';
        metaSpan.textContent = `${analysis.provider}/${analysis.model} — ${analysis.duration}s`;
        aiHeader.appendChild(metaSpan);

        aiBlock.appendChild(aiHeader);

        const aiContent = document.createElement('div');
        aiContent.className = 'ai-analysis-content';
        aiContent.innerHTML = markdownToHtml(analysis.report);
        aiBlock.appendChild(aiContent);
    } else {
        // Pas d'analyse — afficher le bouton pour générer
        aiBlock.appendChild(aiHeader);

        const aiPlaceholder = document.createElement('div');
        aiPlaceholder.className = 'ai-analysis-placeholder';

        const desc = document.createElement('p');
        desc.textContent = 'L\'analyse de sécurité IA n\'a pas encore été générée pour ce scan.';
        aiPlaceholder.appendChild(desc);

        const btn = document.createElement('button');
        btn.className = 'btn-ai-generate';
        btn.innerHTML = '<i class="ph ph-brain"></i> Générer l\'analyse IA';
        btn.addEventListener('click', () => generateAiAnalysis(scanId, aiBlock));
        aiPlaceholder.appendChild(btn);

        aiBlock.appendChild(aiPlaceholder);
    }

    container.appendChild(aiBlock);
}

async function generateAiAnalysis(scanId, aiBlock) {
    // Remplacer le contenu par un loader
    const placeholder = aiBlock.querySelector('.ai-analysis-placeholder');
    if (placeholder) {
        placeholder.innerHTML = '<div class="ai-loading"><i class="ph ph-spinner-gap spin"></i> Génération de l\'analyse en cours... (30-60s)</div>';
    }

    try {
        const res = await fetch(`${API}/${scanId}/analysis`);
        const result = await res.json();

        if (res.ok && result.status === 'success' && result.data) {
            const analysis = result.data;

            // Mettre à jour le header avec les métadonnées
            const header = aiBlock.querySelector('.ai-analysis-header');
            const existingMeta = header.querySelector('.ai-analysis-meta');
            if (existingMeta) existingMeta.remove();
            const metaSpan = document.createElement('span');
            metaSpan.className = 'ai-analysis-meta';
            metaSpan.textContent = `${analysis.provider}/${analysis.model} — ${analysis.duration}s`;
            header.appendChild(metaSpan);

            // Remplacer le placeholder par le contenu
            if (placeholder) placeholder.remove();
            const aiContent = document.createElement('div');
            aiContent.className = 'ai-analysis-content';
            aiContent.innerHTML = markdownToHtml(analysis.report);
            aiBlock.appendChild(aiContent);
        } else {
            const errMsg = result.detail || 'Erreur inconnue';
            if (placeholder) {
                placeholder.innerHTML = `<div class="ai-error"><i class="ph ph-warning"></i> ${errMsg}</div>`;
            }
        }
    } catch (err) {
        if (placeholder) {
            placeholder.innerHTML = '<div class="ai-error"><i class="ph ph-warning"></i> Erreur de connexion au serveur</div>';
        }
    }
}

function renderModalContent(data) {
    const dur = data.summary?.total_duration
        ? ` (Durée : ${data.summary.total_duration}s)`
        : '';

    modalTitle.textContent = '';
    const titleText = document.createTextNode(`Rapport — ${data.target}${dur}`);
    modalTitle.appendChild(titleText);

    if (!data.subdomains || !data.subdomains.length) {
        modalBody.replaceChildren();
        const p = document.createElement('p');
        p.className = 'no-data';
        p.textContent = 'Aucun résultat disponible pour ce scan.';
        modalBody.appendChild(p);
        return;
    }

    modalBody.replaceChildren();

    // ── AI Analysis (en haut du rapport) ──
    renderAiAnalysis(data, modalBody);

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

        // ── Construire la carte (DOM sécurisé)
        const card = document.createElement('div');
        card.className = 'sd-card';

        // Header
        const header = document.createElement('div');
        header.className = 'sd-header';

        const h4 = document.createElement('h4');
        const icon = document.createElement('i');
        icon.className = 'ph ph-link';
        h4.appendChild(icon);
        h4.appendChild(document.createTextNode(' ' + sd.subdomain));

        // Badge ORIGIN_SERVER
        if (sd.tags && sd.tags.includes('ORIGIN_SERVER')) {
            const originBadge = document.createElement('span');
            originBadge.className = 'badge-origin';
            originBadge.title = 'IP serveur origine découverte via headers HTTP (derrière Cloudflare)';
            const shieldIcon = document.createElement('i');
            shieldIcon.className = 'ph ph-shield-warning';
            originBadge.appendChild(shieldIcon);
            originBadge.appendChild(document.createTextNode(' ORIGIN SERVER'));
            h4.appendChild(originBadge);
        }

        const ipsSpan = document.createElement('span');
        ipsSpan.className = 'sd-ips';
        const ipElements = (sd.ips || []).map(ip => {
            const isCf = sd.ip_meta?.[ip]?.is_cloudflare ?? false;
            if (isCf) {
                return `<span class="badge-cf" title="IP Cloudflare (Proxy)"><i class="ph ph-cloud"></i> ${ip}</span>`;
            } else {
                return `<span class="badge-real" title="IP Réelle"><i class="ph ph-server"></i> ${ip}</span>`;
            }
        });
        ipsSpan.innerHTML = ipElements.join('');

        header.appendChild(h4);
        header.appendChild(ipsSpan);
        card.appendChild(header);

        // Body
        const body = document.createElement('div');
        body.className = 'sd-body';

        // ── Ports ouverts
        const portsRow = document.createElement('div');
        portsRow.className = 'info-row';
        const portsLabel = document.createElement('span');
        portsLabel.className = 'info-label';
        portsLabel.textContent = 'Ports ouverts';
        portsRow.appendChild(portsLabel);

        const portsTags = document.createElement('div');
        portsTags.className = 'tags';
        if (allPorts.length) {
            allPorts.forEach(p => {
                const tag = document.createElement('span');
                tag.className = 'tag-port';
                tag.textContent = `${p.port}/${p.proto} — ${p.service} [${p.ip}]`;
                portsTags.appendChild(tag);
            });
        } else {
            const noData = document.createElement('span');
            noData.className = 'no-data';
            noData.textContent = 'Aucun port ouvert détecté';
            portsTags.appendChild(noData);
        }
        portsRow.appendChild(portsTags);
        body.appendChild(portsRow);

        // ── DNS
        const dnsRow = document.createElement('div');
        dnsRow.className = 'info-row';
        const dnsLabel = document.createElement('span');
        dnsLabel.className = 'info-label';
        dnsLabel.textContent = 'DNS';
        dnsRow.appendChild(dnsLabel);

        const dnsContent = document.createElement('div');
        let hasDns = false;
        if (ns.length) {
            const d = document.createElement('div');
            d.className = 'dns-row';
            d.textContent = 'NS : ' + ns.join(', ');
            dnsContent.appendChild(d);
            hasDns = true;
        }
        if (mx.length) {
            const d = document.createElement('div');
            d.className = 'dns-row';
            d.textContent = 'MX : ' + mx.join(', ');
            dnsContent.appendChild(d);
            hasDns = true;
        }
        if (cname) {
            const d = document.createElement('div');
            d.className = 'dns-row';
            d.textContent = 'CNAME : ' + cname;
            dnsContent.appendChild(d);
            hasDns = true;
        }
        if (!hasDns) {
            const noData = document.createElement('span');
            noData.className = 'no-data';
            noData.textContent = 'Aucun enregistrement DNS spécial';
            dnsContent.appendChild(noData);
        }
        dnsRow.appendChild(dnsContent);
        body.appendChild(dnsRow);

        // ── Services Web
        const webRow = document.createElement('div');
        webRow.className = 'info-row';
        const webLabel = document.createElement('span');
        webLabel.className = 'info-label';
        webLabel.textContent = 'Services web';
        webRow.appendChild(webLabel);

        const webContainer = document.createElement('div');
        webContainer.style.cssText = 'flex:1;display:flex;flex-direction:column;gap:8px';

        if (sd.services_web && sd.services_web.length) {
            sd.services_web.forEach(sw => {
                const webBlock = document.createElement('div');
                webBlock.className = 'web-block';

                const wbHeader = document.createElement('div');
                wbHeader.className = 'web-block-header';

                const urlLink = document.createElement('a');
                urlLink.href = sw.url;
                urlLink.target = '_blank';
                urlLink.rel = 'noopener noreferrer';
                urlLink.textContent = sw.url;
                wbHeader.appendChild(urlLink);

                const statusBadge = document.createElement('span');
                const statusClass = sw.status_code === 200 ? 's200'
                    : (sw.status_code === 403 ? 's403' : 's301');
                statusBadge.className = 'status-badge ' + statusClass;
                statusBadge.textContent = sw.status_code;
                wbHeader.appendChild(statusBadge);

                if (sw.final_url && sw.final_url !== sw.url) {
                    const redirect = document.createElement('span');
                    redirect.style.cssText = 'font-size:11px;color:var(--text3)';
                    redirect.textContent = '→ ' + sw.final_url;
                    wbHeader.appendChild(redirect);
                }

                webBlock.appendChild(wbHeader);

                const wbBody = document.createElement('div');
                wbBody.className = 'web-block-body';

                // Technologies
                const techRow = document.createElement('div');
                techRow.className = 'info-row';
                const techLabel = document.createElement('span');
                techLabel.className = 'info-label';
                techLabel.textContent = 'Technologies';
                techRow.appendChild(techLabel);

                const techTags = document.createElement('div');
                techTags.className = 'tags';

                const details = sw.technology_details || [];
                if (details.length) {
                    details.forEach(det => {
                        const tag = document.createElement('span');
                        tag.className = 'tag-tech-detail';
                        tag.title = det.evidence || '';

                        const nameSpan = document.createTextNode(det.name);
                        tag.appendChild(nameSpan);

                        if (det.version) {
                            const verBadge = document.createElement('span');
                            verBadge.className = 'tag-tech-version';
                            verBadge.textContent = det.version;
                            tag.appendChild(verBadge);
                        }

                        const confBadge = document.createElement('span');
                        confBadge.className = 'confidence-badge confidence-' + (det.confidence || 'medium');
                        confBadge.textContent = det.confidence || 'medium';
                        tag.appendChild(confBadge);

                        techTags.appendChild(tag);
                    });
                } else if (sw.technologies && sw.technologies.length) {
                    sw.technologies.forEach(t => {
                        const tag = document.createElement('span');
                        tag.className = 'tag-tech';
                        tag.textContent = t;
                        techTags.appendChild(tag);
                    });
                } else {
                    const noData = document.createElement('span');
                    noData.className = 'no-data';
                    noData.textContent = 'Aucune technologie détectée';
                    techTags.appendChild(noData);
                }
                techRow.appendChild(techTags);
                wbBody.appendChild(techRow);

                // Leaked Origin IPs
                if (sw.leaked_origin_ips && sw.leaked_origin_ips.length) {
                    const leakRow = document.createElement('div');
                    leakRow.className = 'info-row';
                    const leakLabel = document.createElement('span');
                    leakLabel.className = 'info-label';
                    leakLabel.textContent = 'Origine';
                    leakRow.appendChild(leakLabel);

                    const leakTags = document.createElement('div');
                    leakTags.className = 'tags';
                    sw.leaked_origin_ips.forEach(ip => {
                        const tag = document.createElement('span');
                        tag.className = 'tag-leaked-ip';
                        tag.title = 'IP serveur origine leakée via headers HTTP';
                        const si = document.createElement('i');
                        si.className = 'ph ph-shield-warning';
                        tag.appendChild(si);
                        tag.appendChild(document.createTextNode(' ' + ip));
                        leakTags.appendChild(tag);
                    });
                    leakRow.appendChild(leakTags);
                    wbBody.appendChild(leakRow);
                }

                // Endpoints
                if (sw.endpoints && sw.endpoints.length) {
                    const epRow = document.createElement('div');
                    epRow.className = 'info-row';
                    const epLabel = document.createElement('span');
                    epLabel.className = 'info-label';
                    epLabel.textContent = 'Endpoints';
                    epRow.appendChild(epLabel);

                    const epList = document.createElement('ul');
                    epList.className = 'ep-list';
                    sw.endpoints.forEach(ep => {
                        const li = document.createElement('li');
                        const pathSpan = document.createElement('span');
                        pathSpan.textContent = ep.path;
                        li.appendChild(pathSpan);

                        const statusSpan = document.createElement('span');
                        statusSpan.className = 'c' + ep.status_code;
                        statusSpan.textContent = ep.status_code;
                        li.appendChild(statusSpan);

                        epList.appendChild(li);
                    });
                    epRow.appendChild(epList);
                    wbBody.appendChild(epRow);
                }

                webBlock.appendChild(wbBody);
                webContainer.appendChild(webBlock);
            });
        } else {
            const noData = document.createElement('span');
            noData.className = 'no-data';
            noData.textContent = 'Aucun service web détecté sur cette cible';
            webContainer.appendChild(noData);
        }

        webRow.appendChild(webContainer);
        body.appendChild(webRow);
        card.appendChild(body);
        modalBody.appendChild(card);
    });

    // ── CPE Matches
    const cpeMatches = data.cpe_matches || [];
    if (cpeMatches.length) {
        const cpeBlock = document.createElement('div');
        cpeBlock.className = 'cpe-block';

        const cpeTitle = document.createElement('div');
        cpeTitle.className = 'cpe-block-title';

        const shieldIcon = document.createElement('i');
        shieldIcon.className = 'ph ph-shield-warning';
        cpeTitle.appendChild(shieldIcon);
        cpeTitle.appendChild(document.createTextNode(
            `CPE Matches (${cpeMatches.length} technologies identifiées)`
        ));
        cpeBlock.appendChild(cpeTitle);

        cpeMatches.forEach(match => {
            const entry = document.createElement('div');
            entry.className = 'cpe-entry';

            const tech = document.createElement('span');
            tech.className = 'cpe-tech';
            tech.textContent = match.technology + (match.version ? ' ' + match.version : '');
            entry.appendChild(tech);

            const uri = document.createElement('span');
            uri.className = 'cpe-uri';
            uri.textContent = match.cpe_uri;
            entry.appendChild(uri);

            const link = document.createElement('a');
            link.className = 'cpe-link';
            link.href = 'https://nvd.nist.gov/vuln/search/results?cpe_version=cpe%3A%2F'
                + encodeURIComponent(match.cpe_uri);
            link.target = '_blank';
            link.rel = 'noopener noreferrer';
            link.textContent = 'NVD →';
            entry.appendChild(link);

            cpeBlock.appendChild(entry);
        });

        modalBody.appendChild(cpeBlock);
    }
}

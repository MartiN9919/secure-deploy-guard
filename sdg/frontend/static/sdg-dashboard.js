/**
 * Secure Deploy Guard — Dashboard renderer.
 * Uses safe DOM APIs (textContent/createElement) only; no innerHTML with user data.
 */

(function () {
    'use strict';

    const els = {
        scanForm: document.getElementById('scanForm'),
        scanPath: document.getElementById('scanPath'),
        scanRole: document.getElementById('scanRole'),
        scanEnv: document.getElementById('scanEnv'),
        autoApprove: document.getElementById('autoApprove'),
        fullPipeline: document.getElementById('fullPipeline'),
        btnScan: document.getElementById('btnScan'),
        btnRedTeam: document.getElementById('btnRedTeam'),
        btnExportMd: document.getElementById('btnExportMd'),
        btnExportJson: document.getElementById('btnExportJson'),
        spinner: document.getElementById('spinnerOverlay'),
        resultContainer: document.getElementById('resultContainer'),
        statCritical: document.getElementById('statCritical'),
        statHigh: document.getElementById('statHigh'),
        statMedium: document.getElementById('statMedium'),
        statLow: document.getElementById('statLow'),
        trustBar: document.getElementById('trustBar'),
        trustText: document.getElementById('trustText'),
        passBadge: document.getElementById('passBadge'),
        findingsTableBody: document.getElementById('findingsTableBody'),
        findingsFilter: document.getElementById('findingsFilter'),
        agentLog: document.getElementById('agentLog'),
        policyLog: document.getElementById('policyLog'),
        rawResults: document.getElementById('rawResults'),
        resultCards: document.getElementById('resultCards'),
        errorAlert: document.getElementById('errorAlert'),
        errorText: document.getElementById('errorText'),
        greenPanel: document.getElementById('greenPanel'),
        greenList: document.getElementById('greenList'),
    };

    let currentResult = null;
    let currentFindings = [];

    function setLoading(active) {
        els.spinner.classList.toggle('active', active);
        els.btnScan.disabled = active;
        els.btnRedTeam.disabled = active;
    }

    function showError(message) {
        els.errorText.textContent = message;
        els.errorAlert.classList.remove('d-none');
        hideResults();
    }

    function hideError() {
        els.errorAlert.classList.add('d-none');
    }

    function hideResults() {
        els.resultCards.classList.add('d-none');
    }

    function showResults() {
        els.resultCards.classList.remove('d-none');
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = String(text ?? '');
        return div.innerHTML;
    }

    function severityClass(severity) {
        const s = String(severity).toLowerCase();
        return 'severity-' + (['critical', 'high', 'medium', 'low'].includes(s) ? s : 'low');
    }

    function badgeClass(severity) {
        const s = String(severity).toLowerCase();
        const map = {
            critical: 'bg-danger',
            high: 'bg-warning text-dark',
            medium: 'bg-info text-dark',
            low: 'bg-success',
        };
        return map[s] || 'bg-secondary';
    }

    function renderStats(summary) {
        const by = summary && summary.by_severity ? summary.by_severity : {};
        els.statCritical.textContent = by.critical || 0;
        els.statHigh.textContent = by.high || 0;
        els.statMedium.textContent = by.medium || 0;
        els.statLow.textContent = by.low || 0;
    }

    function renderTrustScore(score, passed) {
        const pct = Math.max(0, Math.min(100, Math.round((score || 0) * 100)));
        let color = 'bg-success';
        if (pct < 50) color = 'bg-danger';
        else if (pct < 75) color = 'bg-warning';

        els.trustBar.className = 'bar ' + color;
        els.trustBar.style.width = pct + '%';
        els.trustBar.textContent = pct + '%';
        els.trustText.textContent = 'Trust Score: ' + (score ?? 0).toFixed(2);

        els.passBadge.className = 'badge ' + (passed ? 'bg-success' : 'bg-danger');
        els.passBadge.textContent = passed ? 'PASSED' : 'FAILED';
    }

    function renderFindings(findings) {
        currentFindings = findings || [];
        applyFilter();
    }

    function applyFilter() {
        const filter = els.findingsFilter.value.toLowerCase();
        const tbody = els.findingsTableBody;
        tbody.innerHTML = '';

        const filtered = currentFindings.filter(f => {
            const text = [f.message, f.category, f.file, f.severity].join(' ').toLowerCase();
            return text.includes(filter);
        });

        if (filtered.length === 0) {
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 5;
            td.className = 'text-center text-muted py-4';
            td.textContent = 'No findings match your filter.';
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
        }

        filtered.forEach(f => {
            const tr = document.createElement('tr');
            tr.className = 'finding-row ' + severityClass(f.severity);

            const tdSev = document.createElement('td');
            const badge = document.createElement('span');
            badge.className = 'badge ' + badgeClass(f.severity) + ' badge-severity';
            badge.textContent = String(f.severity).toUpperCase();
            tdSev.appendChild(badge);

            const tdCat = document.createElement('td');
            tdCat.textContent = f.category;

            const tdMsg = document.createElement('td');
            tdMsg.textContent = f.message;

            const tdFile = document.createElement('td');
            const line = f.line ? ':' + f.line : '';
            tdFile.textContent = (f.file || '') + line;

            const tdRec = document.createElement('td');
            tdRec.textContent = f.recommendation || '—';

            tr.appendChild(tdSev);
            tr.appendChild(tdCat);
            tr.appendChild(tdMsg);
            tr.appendChild(tdFile);
            tr.appendChild(tdRec);
            tbody.appendChild(tr);
        });
    }

    function renderAgentLog(agentsRun) {
        const container = els.agentLog;
        container.innerHTML = '';
        if (!agentsRun || agentsRun.length === 0) {
            container.textContent = 'No agents executed.';
            return;
        }
        agentsRun.forEach(agent => {
            const div = document.createElement('div');
            div.className = 'log-entry';
            div.textContent = '✓ ' + agent;
            container.appendChild(div);
        });
    }

    function renderPolicyLog(result) {
        const container = els.policyLog;
        container.innerHTML = '';
        const structural = result.structural_gate ?? 'Allowed';
        const semantic = result.semantic_gate ?? 'Not triggered';
        const approval = result.approval_status ?? 'Not required';
        [
            'Structural Gate: ' + structural,
            'Semantic Gate: ' + semantic,
            'Approval Status: ' + approval,
        ].forEach(line => {
            const div = document.createElement('div');
            div.className = 'log-entry';
            div.textContent = line;
            container.appendChild(div);
        });
    }

    function renderGreenPanel(fixes) {
        const panel = els.greenPanel;
        const list = els.greenList;
        list.innerHTML = '';
        if (!fixes || fixes.length === 0) {
            panel.classList.add('d-none');
            return;
        }
        panel.classList.remove('d-none');
        fixes.forEach(fix => {
            const li = document.createElement('li');
            li.className = 'list-group-item bg-dark text-light border-secondary';
            li.textContent = (fix.file || '') + ':' + (fix.line || '?') + ' — ' + (fix.suggestion || 'No suggestion');
            list.appendChild(li);
        });
    }

    function renderScanResult(result) {
        currentResult = result;
        hideError();

        if (result.error) {
            showError(result.error);
            if (result.report) {
                renderStats(result.report.summary);
                renderFindings(result.report.findings);
                showResults();
            }
            return;
        }

        const summary = result.summary || {};
        const report = result.report || {};
        renderStats(summary);
        renderTrustScore(result.trust_score, result.passed);
        renderFindings(report.findings);
        renderAgentLog(summary.agents_run);
        renderPolicyLog(result);
        renderGreenPanel(result.green_fixes || result.green_team_fixes);
        els.rawResults.textContent = JSON.stringify(result, null, 2);
        showResults();
    }

    function renderFullPipelineResult(result) {
        renderScanResult(result);
    }

    function renderRedTeamResult(result) {
        currentResult = result;
        hideError();
        renderStats({ by_severity: { high: result.summary?.total || 0 } });
        renderTrustScore(0.5, result.summary?.total === 0);
        const findings = (result.findings || []).map(f => ({
            severity: 'high',
            category: f.type,
            message: 'Pattern: ' + f.pattern,
            file: f.file,
            line: 0,
            recommendation: 'Review and remove adversarial content',
        }));
        renderFindings(findings);
        renderAgentLog(['red_team']);
        els.rawResults.textContent = JSON.stringify(result, null, 2);
        showResults();
    }

    async function postForm(url, formData) {
        const resp = await fetch(url, { method: 'POST', body: formData });
        if (!resp.ok) {
            const text = await resp.text();
            throw new Error('HTTP ' + resp.status + ': ' + text);
        }
        return await resp.json();
    }

    async function loadConfig() {
        try {
            const resp = await fetch('/api/config');
            const data = await resp.json();
            populateSelect(els.scanRole, data.roles);
            populateSelect(els.scanEnv, data.environments);
        } catch (err) {
            console.error('Failed to load config', err);
        }
    }

    function populateSelect(select, values) {
        select.innerHTML = '';
        values.forEach(v => {
            const opt = document.createElement('option');
            opt.value = v;
            opt.textContent = v;
            select.appendChild(opt);
        });
    }

    els.scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const form = new FormData();
            form.append('path', els.scanPath.value);
            form.append('role', els.scanRole.value);
            form.append('env', els.scanEnv.value);
            form.append('auto_approve', els.autoApprove.checked);
            form.append('full_pipeline', els.fullPipeline.checked);
            const data = await postForm('/api/scan', form);
            renderScanResult(data);
        } catch (err) {
            showError(err.message);
        } finally {
            setLoading(false);
        }
    });

    els.btnRedTeam.addEventListener('click', async () => {
        setLoading(true);
        try {
            const form = new FormData();
            form.append('path', els.scanPath.value);
            const data = await postForm('/api/scan/red-team', form);
            renderRedTeamResult(data);
        } catch (err) {
            showError(err.message);
        } finally {
            setLoading(false);
        }
    });

    els.btnExportJson.addEventListener('click', () => {
        if (!currentResult) return;
        const blob = new Blob([JSON.stringify(currentResult, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'sdg-report.json';
        a.click();
        URL.revokeObjectURL(url);
    });

    els.btnExportMd.addEventListener('click', () => {
        if (!currentResult || !currentResult.report_markdown) return;
        const blob = new Blob([currentResult.report_markdown], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'sdg-report.md';
        a.click();
        URL.revokeObjectURL(url);
    });

    els.findingsFilter.addEventListener('input', applyFilter);

    loadConfig();
})();

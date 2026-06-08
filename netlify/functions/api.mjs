import crypto from 'crypto';

let seeded = false;

async function getStore() {
    const { getStore } = await import('@netlify/blobs');
    return getStore('forensic-data');
}

async function readJSON(key) {
    try {
        const store = await getStore();
        const raw = await store.get(key);
        return raw ? JSON.parse(raw) : null;
    } catch { return null; }
}

async function writeJSON(key, data) {
    const store = await getStore();
    await store.set(key, JSON.stringify(data, null, 2));
}

async function seedData() {
    if (seeded) return;
    try {
        let pd = await readJSON('pinsv2');
        if (!pd) {
            pd = { masterPin: '1188', pins: [] };
            await writeJSON('pinsv2', pd);
            console.log('[API] Seeded pinsv2');
        }
        let rd = await readJSON('resultsv2');
        if (!rd) {
            rd = [];
            await writeJSON('resultsv2', rd);
            console.log('[API] Seeded resultsv2');
        }
        seeded = true;
    } catch (e) {
        console.log('[API] seedData error:', e.message);
        seeded = true;
    }
}

function isMaster(pin) { return String(pin) === '1188'; }

function isAdmin(headers) {
    const p = headers.get('x-admin-pin') || '';
    return isMaster(p.trim());
}

function getConfig() {
    return {
        discordWebhook: process.env.DISCORD_WEBHOOK || '',
        virustotalKey: process.env.VIRUSTOTAL_API_KEY || ''
    };
}

async function sendWebhook(event, data) {
    const config = getConfig();
    if (!config.discordWebhook) return;
    const embeds = {
        pinCreated: { title: '🔑 PIN Generated', color: 0xE8102D, fields: [
            { name: 'PIN', value: `||${data.pin}||`, inline: true },
            { name: 'By', value: data.createdBy || '—', inline: true }
        ], timestamp: new Date().toISOString() },
        scanStarted: { title: '🔍 Scan Started', color: 0xFF8800, fields: [
            { name: 'PIN', value: `||${data.pin}||`, inline: true },
            { name: 'Computer', value: data.computerName || '—', inline: true }
        ], timestamp: new Date().toISOString() },
        scanCompleted: { title: '✅ Scan Completed', color: 0x22C55E, fields: [
            { name: 'PIN', value: `||${data.pin}||`, inline: true },
            { name: 'Computer', value: data.computerName || '—', inline: true },
            { name: 'Risk Score', value: String(data.riskScore ?? '—'), inline: true },
            { name: 'Detections', value: String(data.detectionCount ?? 0), inline: true }
        ], timestamp: new Date().toISOString() },
        riskDetected: { title: '🚨 Risk Detected', color: 0xE8102D, fields: [
            { name: 'PIN', value: `||${data.pin}||`, inline: true },
            { name: 'Score', value: String(data.riskScore ?? '—'), inline: true },
            { name: 'Details', value: (data.details || '').slice(0, 200), inline: false }
        ], timestamp: new Date().toISOString() }
    };
    try {
        await fetch(config.discordWebhook, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ embeds: [embeds[event] || embeds.scanCompleted] })
        });
    } catch {}
}

function json(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Pin', 'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS' }
    });
}

function error(msg, status = 400) {
    return json({ error: msg }, status);
}

// ─── String Analysis (unchanged) ────────────────────────────
function analyzeStrings(text) {
    const findings = [];
    if (!text) return findings;
    const patterns = [
        { name: 'Email', regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, type: 'email' },
        { name: 'URL', regex: /https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)/g, type: 'url' },
        { name: 'Domain', regex: /(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}/g, type: 'domain' },
        { name: 'IPv4', regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, type: 'ipv4' },
        { name: 'IPv6', regex: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g, type: 'ipv6' }
    ];
    const seen = new Set();
    patterns.forEach(p => {
        let match;
        while ((match = p.regex.exec(text)) !== null) {
            const key = p.type + ':' + match[0];
            if (!seen.has(key)) { seen.add(key); findings.push({ type: p.name, category: p.type, value: match[0], context: extractContext(text, match.index) }); }
        }
    });
    return findings;
}

function extractContext(text, index, radius = 40) {
    const start = Math.max(0, index - radius);
    const end = Math.min(text.length, index + radius);
    let ctx = text.slice(start, end).replace(/\n/g, ' ');
    if (start > 0) ctx = '...' + ctx;
    if (end < text.length) ctx = ctx + '...';
    return ctx;
}

// ─── Timeline (unchanged) ────────────────────────────────────
function buildTimeline(scan) {
    const events = [];
    const baseTime = scan.createdAt || scan.scanDate || new Date().toISOString();
    events.push({ timestamp: baseTime, type: 'scan', category: 'System', description: `Scan started on ${scan.computerName || 'unknown'}`, severity: 'info', source: scan.scanId });
    if (scan.fileSystem) Object.keys(scan.fileSystem).forEach(cat => (scan.fileSystem[cat] || []).forEach(item => { if (item.timestamp) events.push({ timestamp: item.timestamp, type: 'file', category: `FS - ${cat}`, description: item.path || '?', severity: 'info', source: scan.scanId }); }));
    if (scan.registry) Object.keys(scan.registry).forEach(cat => (scan.registry[cat] || []).forEach(item => { if (item.timestamp) events.push({ timestamp: item.timestamp, type: 'registry', category: `Reg - ${cat}`, description: item.key || '?', severity: 'info', source: scan.scanId }); }));
    (scan.processes || []).forEach(p => { if (p.timestamp) events.push({ timestamp: p.timestamp, type: 'process', category: 'Process', description: `${p.name || '?'} (PID: ${p.pid || '?'})`, severity: 'info', source: scan.scanId }); });
    (scan.detections || []).forEach(d => events.push({ timestamp: d.timestamp || baseTime, type: 'threat', category: 'Detection', description: d.name || '?', severity: (d.severity || 'medium').toLowerCase(), source: scan.scanId, detail: d.description || '' }));
    events.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    return events;
}

// ─── Request Handler ─────────────────────────────────────────
export default async (req) => {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, '');
    const method = req.method.toUpperCase();

    if (method === 'OPTIONS') return json({});

    try {
        await seedData();

        // ── Health ──────────────────────────────────────
        if (path === '/api/health') {
            const pd = await readJSON('pinsv2');
            return json({ status: 'ok', timestamp: new Date().toISOString(), pinCount: pd ? pd.pins.length + 1 : 0 });
        }

        // ── Serve pins.json ────────────────────────────
        if (path === '/api/data/pins' || path === '/data/pins.json') {
            const pd = await readJSON('pinsv2');
            return json(pd || { masterPin: '1188', pins: [] });
        }

        // ── Serve results.json ─────────────────────────
        if (path === '/api/data/results' || path === '/data/results.json') {
            const rd = await readJSON('resultsv2');
            return json(rd || []);
        }

        // ── Validate PIN (new flow) ─────────────────────
        if (path === '/api/validate-pin' && method === 'POST') {
            const body = await req.json();
            const pin = String(body.pin || '').trim();
            if (!pin) return error('PIN required');
            if (isMaster(pin)) return json({ isValid: true, sessionId: 'MCK-000', scanType: 'Full System Scan', username: 'tonch', master: true });
            const pd = await readJSON('pinsv2');
            if (!pd) return json({ isValid: false, errorMessage: 'No PIN data available' }, 404);
            const entry = pd.pins.find(p => String(p.pin) === pin);
            if (!entry) return json({ isValid: false, errorMessage: 'PIN not found' }, 404);
            if (!entry.active) return json({ isValid: false, errorMessage: 'PIN is disabled' }, 400);
            if ((entry.usesRemaining ?? 1) <= 0) return json({ isValid: false, errorMessage: 'PIN has no remaining uses' }, 400);
            return json({ isValid: true, sessionId: entry.sessionId || `MCK-${String(pd.pins.indexOf(entry) + 1).padStart(3, '0')}`, scanType: 'Full System Scan', username: entry.createdBy || entry.createdBy || 'analyst' });
        }

        // ── Use PIN (decrement usesRemaining) ──────────
        if (path === '/api/use-pin' && method === 'POST') {
            const body = await req.json();
            const pin = String(body.pin || '').trim();
            if (!pin) return error('PIN required');
            if (isMaster(pin)) return json({ success: true, master: true });
            const pd = await readJSON('pinsv2');
            if (!pd) return error('No PIN data', 404);
            const entry = pd.pins.find(p => String(p.pin) === pin);
            if (!entry) return json({ success: false, error: 'PIN not found' }, 404);
            if (!entry.active) return json({ success: false, error: 'PIN is disabled' }, 400);
            if ((entry.usesRemaining ?? 1) <= 0) return json({ success: false, error: 'No remaining uses' }, 400);
            entry.usesRemaining = (entry.usesRemaining ?? 1) - 1;
            entry.lastUsed = new Date().toISOString();
            await writeJSON('pinsv2', pd);
            await sendWebhook('scanStarted', { pin, computerName: body.computerName || '—' });
            return json({ success: true, usesRemaining: entry.usesRemaining, sessionId: entry.sessionId || `MCK-${String(pd.pins.indexOf(entry) + 1).padStart(3, '0')}` });
        }

        // ── Upload scan result ─────────────────────────
        if (path === '/api/upload-scan' && method === 'POST') {
            const body = await req.json();
            if (!body.pin) return error('pin required');
            const rd = await readJSON('resultsv2') || [];
            const result = {
                scanId: crypto.randomUUID(),
                pin: body.pin,
                computerName: body.computerName || '—',
                scanDate: new Date().toISOString(),
                detections: body.detections || [],
                riskScore: body.riskScore ?? 0,
                sessionId: body.sessionId || '—',
                fileSystem: body.fileSystem || null,
                registry: body.registry || null,
                processes: body.processes || null,
                totalItems: body.totalItems || 0,
            };
            rd.push(result);
            await writeJSON('resultsv2', rd);

            await sendWebhook('scanCompleted', { pin: body.pin, computerName: body.computerName, riskScore: body.riskScore, detectionCount: (body.detections || []).length });

            if (body.detections && body.detections.length > 0) {
                await sendWebhook('riskDetected', { pin: body.pin, riskScore: body.riskScore, details: body.detections.slice(0, 5).map(d => `${d.name || d.type || '?'}: ${d.description || ''}`).join('\n') });
            }

            return json({ success: true, scanId: result.scanId, schemaVersion: '2.0' }, 201);
        }

        // ── Admin: List PINs ───────────────────────────
        if (path === '/api/admin/pins' && method === 'GET') {
            if (!isAdmin(req.headers)) return error('Unauthorized', 401);
            const pd = await readJSON('pinsv2');
            return json(pd || { masterPin: '1188', pins: [] });
        }

        // ── Admin: Create PIN ──────────────────────────
        if (path === '/api/admin/pins' && method === 'POST') {
            if (!isAdmin(req.headers)) return error('Unauthorized', 401);
            const body = await req.json();
            const pin = String(body.pin || '').trim();
            if (!pin || pin.length < 4) return error('PIN must be at least 4 characters');
            if (isMaster(pin)) return error('Cannot create master PIN');
            const pd = await readJSON('pinsv2');
            if (!pd) return error('No PIN data', 500);
            if (pd.pins.some(p => String(p.pin) === pin)) return error('PIN already exists');
            const entry = {
                pin,
                active: body.active !== false,
                createdAt: new Date().toISOString(),
                usesRemaining: Math.max(1, parseInt(body.usesRemaining) || 1),
                createdBy: 'tonch',
                sessionId: `MCK-${String(pd.pins.length + 1).padStart(3, '0')}`
            };
            pd.pins.push(entry);
            await writeJSON('pinsv2', pd);
            await sendWebhook('pinCreated', { pin, createdBy: 'tonch' });
            return json({ success: true, entry }, 201);
        }

        // ── Admin: Toggle PIN ──────────────────────────
        if (path === '/api/admin/pins/toggle' && method === 'POST') {
            if (!isAdmin(req.headers)) return error('Unauthorized', 401);
            const body = await req.json();
            const pin = String(body.pin || '').trim();
            if (!pin) return error('PIN required');
            if (isMaster(pin)) return error('Cannot toggle master PIN');
            const pd = await readJSON('pinsv2');
            if (!pd) return error('No PIN data', 500);
            const entry = pd.pins.find(p => String(p.pin) === pin);
            if (!entry) return error('PIN not found', 404);
            entry.active = !entry.active;
            await writeJSON('pinsv2', pd);
            return json({ success: true, pin: entry.pin, active: entry.active });
        }

        // ── Admin: Delete PIN ─────────────────────────
        if (path === '/api/admin/pins' && method === 'DELETE') {
            if (!isAdmin(req.headers)) return error('Unauthorized', 401);
            const body = await req.json();
            const pin = String(body.pin || '').trim();
            if (!pin) return error('PIN required');
            if (isMaster(pin)) return error('Cannot delete master PIN');
            const pd = await readJSON('pinsv2');
            if (!pd) return error('No PIN data', 500);
            const idx = pd.pins.findIndex(p => String(p.pin) === pin);
            if (idx === -1) return error('PIN not found', 404);
            pd.pins.splice(idx, 1);
            await writeJSON('pinsv2', pd);
            return json({ success: true });
        }

        // ── Admin: List results ───────────────────────
        if (path === '/api/admin/results' && method === 'GET') {
            if (!isAdmin(req.headers)) return error('Unauthorized', 401);
            const rd = await readJSON('resultsv2');
            return json(rd || []);
        }

        // ── Admin: Stats ──────────────────────────────
        if (path === '/api/admin/stats' && method === 'GET') {
            if (!isAdmin(req.headers)) return error('Unauthorized', 401);
            const pd = await readJSON('pinsv2');
            const rd = await readJSON('resultsv2') || [];
            return json({
                totalPins: pd ? pd.pins.length + 1 : 1,
                activePins: pd ? pd.pins.filter(p => p.active).length + 1 : 1,
                totalScans: rd.length,
                totalDetections: rd.reduce((a, r) => a + (r.detections || []).length, 0),
                avgRiskScore: rd.length ? (rd.reduce((a, r) => a + (r.riskScore || 0), 0) / rd.length).toFixed(1) : 0,
                topComputers: Object.entries(rd.reduce((acc, r) => { const c = r.computerName || '—'; acc[c] = (acc[c] || 0) + 1; return acc; }, {})).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([name, count]) => ({ name, count }))
            });
        }

        // ── Debug pins ────────────────────────────────
        if (path === '/api/debug/pins') {
            if (!isAdmin(req.headers)) return error('Unauthorized', 401);
            const pd = await readJSON('pinsv2');
            return json({ count: pd ? pd.pins.length + 1 : 0, masterPin: pd?.masterPin || '1188', pins: pd?.pins || [] });
        }

        // ── Legacy: List scans ─────────────────────────
        if (path === '/api/scans' && method === 'GET') {
            const rd = await readJSON('resultsv2');
            return json(rd?.map(r => ({ ...r, schemaVersion: '2.0' })) || []);
        }

        // ── Legacy: Dashboard stats ────────────────────
        if (path === '/api/dashboard' && method === 'GET') {
            const pd = await readJSON('pinsv2');
            const rd = await readJSON('resultsv2') || [];
            return json({
                totalPins: pd ? pd.pins.length + 1 : 1,
                activePins: pd ? pd.pins.filter(p => p.active).length + 1 : 1,
                totalScans: rd.length,
                totalDetections: rd.reduce((a, r) => a + (r.detections || []).length, 0),
                avgRiskScore: rd.length ? (rd.reduce((a, r) => a + (r.riskScore || 0), 0) / rd.length).toFixed(1) : 0,
                schemaVersion: '2.0'
            });
        }

        // ── Legacy: Old /api/pins (for backward compat) ─
        if (path === '/api/pins') {
            const pd = await readJSON('pinsv2');
            if (method === 'GET') return json(pd?.pins || []);
            return error('Method not allowed', 405);
        }

        // ── Legacy endpoints (unchanged) ────────────────
        if (path === '/api/analyze-strings' && method === 'POST') {
            const body = await req.json();
            if (!body.text) return error('text field required');
            return json({ findings: analyzeStrings(body.text), count: (body.text || '').length, schemaVersion: '2.0' });
        }

        // ── VirusTotal ──────────────────────────────────
        if (path.startsWith('/api/virustotal/') && method === 'GET') {
            const hash = path.replace('/api/virustotal/', '').toLowerCase().trim();
            if (!hash || !/^[a-f0-9]{32,64}$/.test(hash)) return error('Valid hash required');
            const config = getConfig();
            if (!config.virustotalKey) return error('VirusTotal API key not configured', 503);
            try {
                const vtRes = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, { headers: { 'x-apikey': config.virustotalKey } });
                if (vtRes.status === 404) return json({ found: false, hash });
                if (!vtRes.ok) return error(`VT API error: ${vtRes.status}`, 502);
                const vtData = await vtRes.json();
                const attrs = vtData.data.attributes || {};
                return json({ found: true, hash, malicious: attrs.last_analysis_stats?.malicious || 0, suspicious: attrs.last_analysis_stats?.suspicious || 0, undetected: attrs.last_analysis_stats?.undetected || 0, harmless: attrs.last_analysis_stats?.harmless || 0, total: Object.values(attrs.last_analysis_stats || {}).reduce((a, b) => a + b, 0), meaningful_name: attrs.meaningful_name || '', type_description: attrs.type_description || '', tags: attrs.tags || [], last_analysis_date: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null, permalink: `https://www.virustotal.com/gui/file/${hash}` });
            } catch (e) { return error(`VT lookup failed: ${e.message}`, 502); }
        }

        if (path === '/api/virustotal' && method === 'POST') {
            const body = await req.json();
            if (!Array.isArray(body.hashes) || !body.hashes.length) return error('hashes array required');
            const results = [];
            for (const hash of body.hashes.slice(0, 10)) {
                const h = hash.toLowerCase().trim();
                if (!/^[a-f0-9]{32,64}$/.test(h)) continue;
                try {
                    const config = getConfig();
                    if (!config.virustotalKey) { results.push({ hash: h, error: 'No API key' }); continue; }
                    const vtRes = await fetch(`https://www.virustotal.com/api/v3/files/${h}`, { headers: { 'x-apikey': config.virustotalKey } });
                    if (vtRes.status === 404) { results.push({ hash: h, found: false }); continue; }
                    if (!vtRes.ok) { results.push({ hash: h, error: `HTTP ${vtRes.status}` }); continue; }
                    const vtData = await vtRes.json();
                    const attrs = vtData.data.attributes || {};
                    results.push({ hash: h, found: true, malicious: attrs.last_analysis_stats?.malicious || 0, suspicious: attrs.last_analysis_stats?.suspicious || 0, meaningful_name: attrs.meaningful_name || '' });
                } catch (e) { results.push({ hash: h, error: e.message }); }
            }
            return json({ results, schemaVersion: '2.0' });
        }

        return error(`Not found: ${method} ${path}`, 404);
    } catch (err) {
        return error(err.message, 500);
    }
};

export const config = { path: ['/api/*', '/data/pins.json', '/data/results.json'] };

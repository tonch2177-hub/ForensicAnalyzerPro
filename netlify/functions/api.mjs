import crypto from 'crypto';

const SCHEMA_VERSION = '2.0';

async function getStore() {
    const { getStore } = await import('@netlify/blobs');
    return getStore('forensic-data');
}

async function readJSON(key) {
    try {
        const store = await getStore();
        const raw = await store.get(key);
        return raw ? JSON.parse(raw) : [];
    } catch { return []; }
}

async function writeJSON(key, data) {
    const store = await getStore();
    await store.set(key, JSON.stringify(data, null, 2));
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
        pinCreated: { title: '🔑 New PIN Generated', color: 0xE8102D, fields: [
            { name: 'PIN', value: `||${data.pin}||`, inline: true },
            { name: 'Session', value: data.sessionId, inline: true }
        ], timestamp: new Date().toISOString() },

        pinUsed: { title: '🔍 PIN Used', color: 0xFF8800, fields: [
            { name: 'PIN', value: `||${data.pin}||`, inline: true },
            { name: 'Session', value: data.sessionId, inline: true },
            { name: 'Hostname', value: data.hostname || 'Unknown', inline: true }
        ], timestamp: new Date().toISOString() },

        scanComplete: { title: '✅ Scan Completed', color: 0x22C55E, fields: [
            { name: 'Session', value: data.sessionId, inline: true },
            { name: 'Items', value: String(data.totalItems || 0), inline: true },
            { name: 'IOCs', value: String(data.iocsDetected || 0), inline: true },
            { name: 'Schema', value: SCHEMA_VERSION, inline: true }
        ], timestamp: new Date().toISOString() }
    };

    try {
        await fetch(config.discordWebhook, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ embeds: [embeds[event] || embeds.pinCreated] })
        });
    } catch {}
}

function generatePin() {
    return String(crypto.randomInt(1000, 9999));
}

function nextSessionId(pins, scans) {
    let max = 0;
    [...pins, ...scans].forEach(item => {
        const m = (item.sessionId || '').match(/MCK-(\d+)/);
        if (m) { const n = parseInt(m[1]); if (n > max) max = n; }
    });
    return 'MCK-' + String(max + 1).padStart(3, '0');
}

function json(res, data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
}

function error(res, msg, status = 400) {
    return json(res, { error: msg }, status);
}

function safeJsonParse(str, fallback = {}) {
    if (typeof str === 'object') return str;
    try { return JSON.parse(str); } catch { return fallback; }
}

// ─── String Analysis ─────────────────────────────────────
function analyzeStrings(text) {
    const findings = [];
    if (!text) return findings;

    const patterns = [
        { name: 'Email', regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, type: 'email' },
        { name: 'URL', regex: /https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)/g, type: 'url' },
        { name: 'Domain', regex: /(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}/g, type: 'domain' },
        { name: 'IPv4', regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, type: 'ipv4' },
        { name: 'IPv6', regex: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g, type: 'ipv6' },
        { name: 'Discord ID', regex: /\b\d{17,20}\b/g, type: 'discord_id' },
        { name: 'Username', regex: /\b[a-zA-Z0-9_]{3,32}\b/g, type: 'username' }
    ];

    const seen = new Set();
    patterns.forEach(p => {
        let match;
        while ((match = p.regex.exec(text)) !== null) {
            const key = p.type + ':' + match[0];
            if (!seen.has(key)) {
                seen.add(key);
                findings.push({ type: p.name, category: p.type, value: match[0], context: extractContext(text, match.index) });
            }
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

// ─── Timeline Generation ──────────────────────────────────
function buildTimeline(scan) {
    const events = [];
    const results = safeJsonParse(scan.results);
    const baseTime = scan.createdAt || scan.scanDate || new Date().toISOString();

    // Scan start
    events.push({ timestamp: baseTime, type: 'scan', category: 'System', description: `Scan started on ${scan.hostname || 'unknown'}`, severity: 'info', source: scan.sessionId });

    // Filesystem events
    const fs = results.fileSystem || {};
    Object.keys(fs).forEach(cat => {
        (fs[cat] || []).forEach(item => {
            if (item.timestamp) {
                events.push({ timestamp: item.timestamp, type: 'file', category: `File System - ${cat}`, description: `${item.path || 'Unknown path'}`, severity: 'info', source: scan.sessionId, detail: `Size: ${item.size || '?'} | Hash: ${(item.sha256 || item.hash || '').slice(0, 16)}` });
            }
        });
    });

    // Registry events
    const reg = results.registry || {};
    Object.keys(reg).forEach(cat => {
        (reg[cat] || []).forEach(item => {
            if (item.timestamp) {
                events.push({ timestamp: item.timestamp, type: 'registry', category: `Registry - ${cat}`, description: `${item.key || item.path || 'Unknown key'}`, severity: 'info', source: scan.sessionId, detail: `Value: ${(item.value || '').slice(0, 60)}` });
            }
        });
    });

    // Process events
    (results.processes || []).forEach(p => {
        if (p.timestamp) {
            events.push({ timestamp: p.timestamp, type: 'process', category: 'Process', description: `${p.name || p.process || 'Unknown'} (PID: ${p.pid || '?'})`, severity: p.exitCode && p.exitCode !== '0' ? 'warning' : 'info', source: scan.sessionId, detail: `Exit: ${p.exitCode || '0'} | User: ${p.user || '?'}` });
        }
    });

    // Event log entries
    const el = results.eventLogs || {};
    Object.keys(el).forEach(logName => {
        (el[logName] || []).forEach(e => {
            if (e.timestamp) {
                events.push({ timestamp: e.timestamp, type: 'eventlog', category: `Event Log - ${logName}`, description: `${e.source || 'Unknown'} (ID: ${e.eventId || '?'})`, severity: (e.level || 'info').toLowerCase(), source: scan.sessionId, detail: (e.message || e.msg || '').slice(0, 100) });
            }
        });
    });

    // Threat indicators
    (results.threatIndicators || []).forEach(t => {
        events.push({ timestamp: t.timestamp || baseTime, type: 'threat', category: 'Threat', description: `${t.indicator || t.name || 'Unknown'}`, severity: (t.severity || 'low').toLowerCase(), source: scan.sessionId, detail: t.description || '' });
    });

    // Security tools
    (results.securityTools || []).forEach(t => {
        events.push({ timestamp: t.lastSeen || t.timestamp || baseTime, type: 'tool', category: 'Security Tool', description: `${t.name || 'Unknown'} v${t.version || '?'}`, severity: t.status === 'running' ? 'warning' : 'info', source: scan.sessionId, detail: `Path: ${t.path || '?'}` });
    });

    events.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    return events;
}

// ─── Request Handler ─────────────────────────────────────────
export default async (req) => {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, '');
    const method = req.method.toUpperCase();

    try {
        // ── Health ──────────────────────────────────────
        if (path === '/api/health') {
            return json(null, { status: 'ok', timestamp: new Date().toISOString(), schemaVersion: SCHEMA_VERSION, features: ['pins', 'scans', 'validate-pin', 'timeline', 'analyze-strings', 'virustotal'] });
        }

        // ── Validate PIN ────────────────────────────────
        if (path === '/api/validate-pin' && method === 'POST') {
            const body = await req.json();
            const { pin } = body;
            if (!pin) return error(null, 'PIN is required');

            const pins = await readJSON('pins');
            const entry = pins.find(p => p.pin === pin);

            if (!entry) return json(null, { isValid: false, errorMessage: 'PIN not found' }, 404);
            if (entry.status !== 'active') return json(null, { isValid: false, errorMessage: `PIN is ${entry.status}` }, 400);

            entry.status = 'in_use';
            entry.usedAt = new Date().toISOString();
            await writeJSON('pins', pins);

            await sendWebhook('pinUsed', { pin: entry.pin, sessionId: entry.sessionId, hostname: body.hostname });

            return json(null, { isValid: true, sessionId: entry.sessionId, scanType: 'Full System Scan' });
        }

        // ── Upload Scan ─────────────────────────────────
        if (path === '/api/upload-scan' && method === 'POST') {
            const body = await req.json();
            const { sessionId, pin } = body;
            if (!sessionId || !pin) return error(null, 'sessionId and pin required');

            const scans = await readJSON('scans');
            const scanEntry = { id: crypto.randomUUID(), schemaVersion: SCHEMA_VERSION, ...body, createdAt: new Date().toISOString() };
            scans.push(scanEntry);
            await writeJSON('scans', scans);

            const pins = await readJSON('pins');
            const pinEntry = pins.find(p => p.pin === pin);
            if (pinEntry) {
                pinEntry.status = 'used';
                pinEntry.completedAt = new Date().toISOString();
                await writeJSON('pins', pins);
            }

            // Auto-build timeline on upload
            const timeline = buildTimeline(scanEntry);
            const timelineKey = `timeline:${scanEntry.id}`;
            const store = await getStore();
            await store.set(timelineKey, JSON.stringify(timeline, null, 2));

            await sendWebhook('scanComplete', { sessionId, totalItems: body.totalItems, iocsDetected: body.iocsDetected });

            return json(null, { success: true, id: scanEntry.id, schemaVersion: SCHEMA_VERSION, timelineEvents: timeline.length });
        }

        // ── List / Create Pins ──────────────────────────
        if (path === '/api/pins') {
            if (method === 'GET') {
                const pins = await readJSON('pins');
                return json(null, pins);
            }
            if (method === 'POST') {
                const pins = await readJSON('pins');
                const scans = await readJSON('scans');
                const body = await req.json().catch(() => ({}));
                const pin = generatePin();
                const sessionId = nextSessionId(pins, scans);
                const entry = { pin, sessionId, status: 'active', notes: body.notes || '', createdBy: body.createdBy || 'admin', createdAt: new Date().toISOString() };
                pins.push(entry);
                await writeJSON('pins', pins);
                await sendWebhook('pinCreated', { pin, sessionId });
                return json(null, { pin, sessionId, status: 'active', schemaVersion: SCHEMA_VERSION }, 201);
            }
            return error(null, 'Method not allowed', 405);
        }

        // ── List Scans ──────────────────────────────────
        if (path === '/api/scans' && method === 'GET') {
            const scans = await readJSON('scans');
            return json(null, scans.map(s => ({ ...s, schemaVersion: s.schemaVersion || '1.0' })));
        }

        // ── Dashboard Stats ─────────────────────────────
        if (path === '/api/dashboard' && method === 'GET') {
            const pins = await readJSON('pins');
            const scans = await readJSON('scans');
            return json(null, {
                schemaVersion: SCHEMA_VERSION,
                totalPins: pins.length,
                activePins: pins.filter(p => p.status === 'active').length,
                totalScans: scans.length,
                totalItems: scans.reduce((a, s) => a + (s.totalItems || 0), 0),
                totalIocs: scans.reduce((a, s) => a + (s.iocsDetected || 0), 0),
                scansByVersion: {
                    v1: scans.filter(s => !s.schemaVersion || s.schemaVersion === '1.0').length,
                    v2: scans.filter(s => s.schemaVersion === '2.0').length
                }
            });
        }

        // ── Timeline (by scan ID) ───────────────────────
        if (path.startsWith('/api/timeline/') && method === 'GET') {
            const scanId = path.replace('/api/timeline/', '');
            if (!scanId) return error(null, 'Scan ID required');
            const store = await getStore();
            const raw = await store.get(`timeline:${scanId}`);
            if (raw) return json(null, JSON.parse(raw));
            // Build on demand if not cached
            const scans = await readJSON('scans');
            const scan = scans.find(s => s.id === scanId);
            if (!scan) return error(null, 'Scan not found', 404);
            const timeline = buildTimeline(scan);
            await store.set(`timeline:${scanId}`, JSON.stringify(timeline, null, 2));
            return json(null, timeline);
        }

        // ── All Timelines ───────────────────────────────
        if (path === '/api/timeline' && method === 'GET') {
            const scans = await readJSON('scans');
            const allEvents = [];
            for (const scan of scans.slice(-20)) {
                const events = buildTimeline(scan);
                allEvents.push(...events);
            }
            allEvents.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
            return json(null, allEvents.slice(0, 500));
        }

        // ── Analyze Strings ─────────────────────────────
        if (path === '/api/analyze-strings' && method === 'POST') {
            const body = await req.json();
            const { text } = body;
            if (!text) return error(null, 'text field required');
            const findings = analyzeStrings(text);
            return json(null, { findings, count: findings.length, schemaVersion: SCHEMA_VERSION });
        }

        // ── VirusTotal Hash Lookup ──────────────────────
        if (path.startsWith('/api/virustotal/') && method === 'GET') {
            const hash = path.replace('/api/virustotal/', '').toLowerCase().trim();
            if (!hash || !/^[a-f0-9]{32,64}$/.test(hash)) return error(null, 'Valid MD5/SHA1/SHA256 hash required');
            const config = getConfig();
            if (!config.virustotalKey) return error(null, 'VirusTotal API key not configured on server', 503);
            try {
                const vtRes = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
                    headers: { 'x-apikey': config.virustotalKey }
                });
                if (vtRes.status === 404) return json(null, { found: false, hash, message: 'Hash not found in VirusTotal' });
                if (!vtRes.ok) return error(null, `VirusTotal API error: ${vtRes.status}`, 502);
                const vtData = await vtRes.json();
                const attrs = vtData.data.attributes || {};
                return json(null, {
                    found: true,
                    hash,
                    malicious: attrs.last_analysis_stats?.malicious || 0,
                    suspicious: attrs.last_analysis_stats?.suspicious || 0,
                    undetected: attrs.last_analysis_stats?.undetected || 0,
                    harmless: attrs.last_analysis_stats?.harmless || 0,
                    total: Object.values(attrs.last_analysis_stats || {}).reduce((a, b) => a + b, 0),
                    meaningful_name: attrs.meaningful_name || '',
                    type_description: attrs.type_description || '',
                    tags: attrs.tags || [],
                    last_analysis_date: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
                    permalink: `https://www.virustotal.com/gui/file/${hash}`
                });
            } catch (e) {
                return error(null, `VirusTotal lookup failed: ${e.message}`, 502);
            }
        }

        // ── Bulk Hash Lookup ────────────────────────────
        if (path === '/api/virustotal' && method === 'POST') {
            const body = await req.json();
            const { hashes } = body;
            if (!Array.isArray(hashes) || !hashes.length) return error(null, 'hashes array required');
            const results = [];
            for (const hash of hashes.slice(0, 10)) {
                const h = hash.toLowerCase().trim();
                if (!/^[a-f0-9]{32,64}$/.test(h)) continue;
                try {
                    const config = getConfig();
                    if (!config.virustotalKey) { results.push({ hash: h, error: 'No API key' }); continue; }
                    const vtRes = await fetch(`https://www.virustotal.com/api/v3/files/${h}`, {
                        headers: { 'x-apikey': config.virustotalKey }
                    });
                    if (vtRes.status === 404) { results.push({ hash: h, found: false }); continue; }
                    if (!vtRes.ok) { results.push({ hash: h, error: `HTTP ${vtRes.status}` }); continue; }
                    const vtData = await vtRes.json();
                    const attrs = vtData.data.attributes || {};
                    results.push({
                        hash: h,
                        found: true,
                        malicious: attrs.last_analysis_stats?.malicious || 0,
                        suspicious: attrs.last_analysis_stats?.suspicious || 0,
                        meaningful_name: attrs.meaningful_name || ''
                    });
                } catch (e) { results.push({ hash: h, error: e.message }); }
            }
            return json(null, { results, schemaVersion: SCHEMA_VERSION });
        }

        // ── 404 ─────────────────────────────────────────
        return error(null, `Not found: ${method} ${path}`, 404);
    } catch (err) {
        return error(null, err.message, 500);
    }
};

export const config = { path: '/api/*' };

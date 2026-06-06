import crypto from 'crypto';

// ─── Netlify Blobs ──────────────────────────────────────────
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

// ─── Config (from env or defaults) ──────────────────────────
function getConfig() {
    return {
        discordWebhook: process.env.DISCORD_WEBHOOK || ''
    };
}

// ─── Discord Webhook ────────────────────────────────────────
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
            { name: 'IOCs', value: String(data.iocsDetected || 0), inline: true }
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

// ─── Helpers ─────────────────────────────────────────────────
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

// ─── Request Handler ─────────────────────────────────────────
export default async (req) => {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, '');
    const method = req.method.toUpperCase();

    try {
        // ── Health ──────────────────────────────────────
        if (path === '/api/health') {
            return json(null, { status: 'ok', timestamp: new Date().toISOString() });
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
            const scanEntry = { id: crypto.randomUUID(), ...body, createdAt: new Date().toISOString() };
            scans.push(scanEntry);
            await writeJSON('scans', scans);

            const pins = await readJSON('pins');
            const pinEntry = pins.find(p => p.pin === pin);
            if (pinEntry) {
                pinEntry.status = 'used';
                pinEntry.completedAt = new Date().toISOString();
                await writeJSON('pins', pins);
            }

            await sendWebhook('scanComplete', { sessionId, totalItems: body.totalItems, iocsDetected: body.iocsDetected });

            return json(null, { success: true, id: scanEntry.id });
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
                return json(null, { pin, sessionId, status: 'active' }, 201);
            }
            return error(null, 'Method not allowed', 405);
        }

        // ── List Scans ──────────────────────────────────
        if (path === '/api/scans' && method === 'GET') {
            const scans = await readJSON('scans');
            return json(null, scans);
        }

        // ── Dashboard Stats ─────────────────────────────
        if (path === '/api/dashboard' && method === 'GET') {
            const pins = await readJSON('pins');
            const scans = await readJSON('scans');
            return json(null, {
                totalPins: pins.length,
                activePins: pins.filter(p => p.status === 'active').length,
                totalScans: scans.length,
                totalItems: scans.reduce((a, s) => a + (s.totalItems || 0), 0),
                totalIocs: scans.reduce((a, s) => a + (s.iocsDetected || 0), 0)
            });
        }

        // ── 404 ─────────────────────────────────────────
        return error(null, `Not found: ${method} ${path}`, 404);
    } catch (err) {
        return error(null, err.message, 500);
    }
};

export const config = { path: '/api/*' };

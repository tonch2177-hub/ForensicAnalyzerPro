const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Config ───────────────────────────────────────────────
const CONFIG_PATH = path.join(__dirname, 'config.json');
const PINS_PATH = path.join(__dirname, 'data', 'pins.json');
const SCANS_PATH = path.join(__dirname, 'data', 'scans.json');

function loadConfig() {
    try {
        if (!fs.existsSync(CONFIG_PATH)) {
            const def = { apiUrl: `http://localhost:${PORT}`, discordWebhook: '' };
            fs.writeFileSync(CONFIG_PATH, JSON.stringify(def, null, 2));
            return def;
        }
        return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    } catch { return { apiUrl: `http://localhost:${PORT}`, discordWebhook: '' }; }
}

function loadJSON(file) {
    try {
        if (!fs.existsSync(file)) return [];
        return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch { return []; }
}

function saveJSON(file, data) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ─── Discord Webhook ──────────────────────────────────────
async function sendWebhook(event, data) {
    const config = loadConfig();
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
            { name: 'Status', value: data.status || 'completed', inline: true }
        ], timestamp: new Date().toISOString() },

        error: { title: '❌ System Error', color: 0xEF4444, fields: [
            { name: 'Error', value: data.message || 'Unknown error' }
        ], timestamp: new Date().toISOString() }
    };

    const payload = { embeds: [embeds[event] || embeds.error] };

    try {
        await fetch(config.discordWebhook, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
    } catch (err) {
        console.error('Webhook failed:', err.message);
    }
}

// ─── PIN Management ────────────────────────────────────────
function generatePin() {
    const num = crypto.randomInt(1000, 9999);
    return String(num);
}

function nextSessionId(pins, scans) {
    let max = 0;
    [...pins, ...scans].forEach(item => {
        const m = (item.sessionId || '').match(/MCK-(\d+)/);
        if (m) { const n = parseInt(m[1]); if (n > max) max = n; }
    });
    return 'MCK-' + String(max + 1).padStart(3, '0');
}

// ─── Middleware ─────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// Serve static files (index.html, etc.)
app.use(express.static(path.join(__dirname, '..')));

// ─── API Routes ────────────────────────────────────────────

// Health
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Validate PIN
app.post('/api/validate-pin', async (req, res) => {
    const { pin } = req.body;
    if (!pin) return res.status(400).json({ isValid: false, errorMessage: 'PIN is required' });

    const pins = loadJSON(PINS_PATH);
    const entry = pins.find(p => p.pin === pin);

    if (!entry) {
        return res.status(404).json({ isValid: false, errorMessage: 'PIN not found' });
    }

    if (entry.status !== 'active') {
        return res.status(400).json({ isValid: false, errorMessage: `PIN is ${entry.status}` });
    }

    entry.status = 'in_use';
    entry.usedAt = new Date().toISOString();
    saveJSON(PINS_PATH, pins);

    await sendWebhook('pinUsed', { pin: entry.pin, sessionId: entry.sessionId, hostname: req.body.hostname });

    res.json({
        isValid: true,
        sessionId: entry.sessionId,
        scanType: 'Full System Scan'
    });
});

// Upload scan results
app.post('/api/upload-scan', async (req, res) => {
    const { sessionId, pin } = req.body;
    if (!sessionId || !pin) return res.status(400).json({ success: false, errorMessage: 'sessionId and pin required' });

    const scans = loadJSON(SCANS_PATH);
    const scanEntry = {
        id: crypto.randomUUID(),
        ...req.body,
        createdAt: new Date().toISOString(),
        results: req.body.results || {}
    };
    scans.push(scanEntry);
    saveJSON(SCANS_PATH, scans);

    const pins = loadJSON(PINS_PATH);
    const pinEntry = pins.find(p => p.pin === pin);
    if (pinEntry) {
        pinEntry.status = 'used';
        pinEntry.completedAt = new Date().toISOString();
        saveJSON(PINS_PATH, pins);
    }

    await sendWebhook('scanComplete', {
        sessionId,
        totalItems: req.body.totalItems,
        iocsDetected: req.body.iocsDetected,
        status: req.body.status
    });

    res.json({ success: true, id: scanEntry.id });
});

// Get all pins
app.get('/api/pins', (req, res) => {
    const pins = loadJSON(PINS_PATH);
    res.json(pins);
});

// Create PIN
app.post('/api/pins', async (req, res) => {
    const pins = loadJSON(PINS_PATH);
    const scans = loadJSON(SCANS_PATH);
    const pin = generatePin();
    const sessionId = nextSessionId(pins, scans);

    const entry = {
        pin,
        sessionId,
        status: 'active',
        notes: req.body.notes || '',
        createdBy: req.body.createdBy || 'admin',
        createdAt: new Date().toISOString()
    };
    pins.push(entry);
    saveJSON(PINS_PATH, pins);

    await sendWebhook('pinCreated', { pin: entry.pin, sessionId: entry.sessionId });

    res.json({ pin: entry.pin, sessionId: entry.sessionId });
});

// Get all scans
app.get('/api/scans', (req, res) => {
    const scans = loadJSON(SCANS_PATH);
    res.json(scans);
});

// Get dashboard data
app.get('/api/dashboard', (req, res) => {
    const pins = loadJSON(PINS_PATH);
    const scans = loadJSON(SCANS_PATH);
    res.json({
        totalPins: pins.length,
        activePins: pins.filter(p => p.status === 'active').length,
        totalScans: scans.length,
        totalItems: scans.reduce((a, s) => a + (s.totalItems || 0), 0),
        totalIocs: scans.reduce((a, s) => a + (s.iocsDetected || 0), 0)
    });
});

// ─── Start ─────────────────────────────────────────────────
app.listen(PORT, () => {
    const config = loadConfig();
    console.log(`ForensicAnalyzer Dashboard running on http://localhost:${PORT}`);
    console.log(`API: http://localhost:${PORT}/api/`);
    console.log(`Dashboard: http://localhost:${PORT}/`);
    if (config.discordWebhook) {
        console.log('Discord webhook configured ✓');
    } else {
        console.log('No Discord webhook — set discordWebhook in config.json');
    }
});

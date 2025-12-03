import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const pkg = require('@47ng/opaque-server');
const { ServerSetup, HandleRegistration, HandleLogin } = pkg;

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));

// --- HELPERS ---
const jsonToBin = (arr) => new Uint8Array(arr);
const binToJson = (bytes) => Array.from(bytes);
const strToBytes = (str) => new Uint8Array(Buffer.from(str, 'utf-8'));

// --- SERVER SETUP ---
console.log("Generating FRESH server keys...");
const serverSetup = new ServerSetup(); 
console.log("✅ Server Ready");

let db = {};
let loginStates = {}; 

// --- 🚨 THREAT MONITORING SYSTEM 🚨 ---
let latestThreat = null; // Stores the current attack status

// Helper to set a threat (clears after 3 seconds)
function triggerAlarm(type, message) {
    console.log(`[ALARM] ${type}: ${message}`);
    latestThreat = { type, message, timestamp: Date.now() };
    
    // Auto-reset alarm after 5 seconds
    setTimeout(() => { latestThreat = null; }, 5000);
}

// ROUTE: Frontend calls this to check status
app.get('/system-status', (req, res) => {
    res.json(latestThreat || { type: 'SAFE', message: 'System Normal' });
});

// --- CORE ROUTES ---

app.post('/register-init', async (req, res) => {
    try {
        const { userId, requestArray } = req.body;
        const request = jsonToBin(requestArray);
        const userBytes = strToBytes(userId);
        const handler = new HandleRegistration(serverSetup);
        const response = handler.start(request, userBytes);
        handler.free();
        res.json({ responseArray: binToJson(response) });
    } catch (e) {
        res.status(500).json({ error: e.toString() });
    }
});

app.post('/register-finish', async (req, res) => {
    try {
        const { userId, recordArray } = req.body;
        db[userId] = recordArray;
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.toString() });
    }
});

app.post('/login-init', async (req, res) => {
    try {
        const { userId, startUploadArray } = req.body;
        
        // ATTACK DETECTION: Dictionary Attack
        // If this route is hit rapidly, it triggers a warning
        triggerAlarm('WARNING', `Login Attempt for: ${userId}`);

        if (!db[userId]) return res.status(400).json({ error: "User not found" });

        const record = jsonToBin(db[userId]);
        const request = jsonToBin(startUploadArray);
        const userBytes = strToBytes(userId);

        const handler = new HandleLogin(serverSetup);
        const response = handler.start(record, request, userBytes);

        const state = handler.serialize();
        loginStates[userId] = binToJson(state);
        handler.free();

        res.json({ serverResponseArray: binToJson(response) });
    } catch (e) {
        res.status(500).json({ error: e.toString() });
    }
});

app.post('/login-finish', async (req, res) => {
    try {
        const { userId, clientFinishArray } = req.body;
        const clientFinish = jsonToBin(clientFinishArray);
        const stateArray = loginStates[userId];

        if (!stateArray) return res.status(400).json({ error: "No login state found" });

        const handler = HandleLogin.deserialize(jsonToBin(stateArray));
        const sessionKey = handler.finish(clientFinish);
        handler.free();

        res.json({ success: true, sessionKeyArray: binToJson(sessionKey) });
    } catch (e) {
        res.status(401).json({ error: "Login Failed" });
    }
});

// --- 💀 VULNERABILITY (Offline Attack Trigger) 💀 ---
app.get('/leak-database', (req, res) => {
    // TRIGGER CRITICAL ALARM
    triggerAlarm('CRITICAL', 'DATA BREACH DETECTED! Database Downloaded.');
    
    if (!serverSetup) return res.status(500).json({error: "Server not ready"});

    res.json({
        serverKeys: binToJson(serverSetup.serialize()),
        database: db
    });
});

app.listen(3000, () => console.log('🚀 Server running on http://localhost:3000'));
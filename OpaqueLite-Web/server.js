import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import { createRequire } from 'module';
import fs from 'fs';

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

// --- SERVER KEY PERSISTENCE ---
const KEY_FILE = 'server_keys.bin';
let SERVER_KEY_BYTES;

if (fs.existsSync(KEY_FILE)) {
    console.log("📂 Loading existing Server Keys from disk...");
    const buffer = fs.readFileSync(KEY_FILE);
    SERVER_KEY_BYTES = new Uint8Array(buffer);
} else {
    console.log("🆕 Generating NEW server keys...");
    const tempSetup = new ServerSetup();
    SERVER_KEY_BYTES = tempSetup.serialize();
    tempSetup.free();
    fs.writeFileSync(KEY_FILE, Buffer.from(SERVER_KEY_BYTES));
}


let db = {};
let loginStates = {}; 

// --- 🚨 THREAT MONITORING SYSTEM 🚨 ---
let latestThreat = null;

function triggerAlarm(type, message) {
    console.log(`[ALARM] ${type}: ${message}`);
    latestThreat = { type, message, timestamp: Date.now() };
    setTimeout(() => { latestThreat = null; }, 5000);
}

app.get('/system-status', (req, res) => {
    res.json(latestThreat || { type: 'SAFE', message: 'System Normal' });
});

// --- CORE ROUTES ---

// 1. REGISTER INIT
app.post('/register-init', async (req, res) => {
    try {
        const { userId, requestArray } = req.body;
        console.log(`[Register] Init for: ${userId}`);

        const request = jsonToBin(requestArray);
        const userBytes = strToBytes(userId);

        const handler = new HandleRegistration(serverSetup);
        const response = handler.start(userBytes, request);
        handler.free();

        res.json({ responseArray: binToJson(response) });
    } catch (e) {
        console.error("Reg Init Error:", e);
        res.status(500).json({ error: e.toString() });
    }
});

// 2. REGISTER FINISH
app.post('/register-finish', async (req, res) => {
    try {
        const { userId, recordArray } = req.body;
        console.log(`[Register] Finish for: ${userId}`);
        db[userId] = recordArray;
        res.json({ success: true });
    } catch (e) {
        console.error("Reg Finish Error:", e);
        res.status(500).json({ error: e.toString() });
    }
});

// 3. LOGIN INIT
app.post('/login-init', async (req, res) => {
    try {
        const { userId, startUploadArray } = req.body;
        
        // ATTACK DETECTION
        triggerAlarm('WARNING', `Login Attempt: ${userId}`);

        if (!db[userId]) return res.status(400).json({ error: "User not found" });

        const record = jsonToBin(db[userId]);
        const request = jsonToBin(startUploadArray);
        const userBytes = strToBytes(userId);

        const setup = ServerSetup.deserialize(SERVER_KEY_BYTES);

        const handler = new HandleLogin(serverSetup);
        const response = handler.start(record, userBytes, request);

        const state = handler.serialize();
        loginStates[userId] = binToJson(state);
        handler.free();
        setup.free();

        res.json({ serverResponseArray: binToJson(response) });
    } catch (e) {
        console.error("Login Init Error:", e);
        res.status(500).json({ error: e.toString() });
    }
});

// 4. LOGIN FINISH
app.post('/login-finish', async (req, res) => {
    try {
        const { userId, clientFinishArray } = req.body;
        console.log(`[Login] Finish for: ${userId}`);
        
        const clientFinish = jsonToBin(clientFinishArray);
        const stateArray = loginStates[userId];

        if (!stateArray) return res.status(400).json({ error: "No login state found" });

        const setup = ServerSetup.deserialize(SERVER_KEY_BYTES);

        const handler = HandleLogin.deserialize(jsonToBin(stateArray), serverSetup);
        const sessionKey = handler.finish(clientFinish);

        setup.free();

        console.log("✅ LOGIN SUCCESS!");
        res.json({ success: true, sessionKeyArray: binToJson(sessionKey) });
    } catch (e) {
        console.error("Login Finish Error:", e);
        res.status(401).json({ error: "Login Failed" });
    }
});

// --- 💀 VULNERABILITY (Demo Only) 💀 ---
app.get('/leak-database', (req, res) => {
    triggerAlarm('CRITICAL', 'DATA BREACH! Database Leaked.');
    res.json({
        serverKeys: binToJson(serverSetup.serialize()),
        database: db
    });
});

app.listen(3000, () => console.log('🚀 Server running on http://localhost:3000'));
import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import fs from 'fs';
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

console.log(`✅ Server Ready (Keys loaded: ${SERVER_KEY_BYTES.length} bytes)`);

// --- DATABASE ---
const DB_FILE = 'database.json';
let db = {};

if (fs.existsSync(DB_FILE)) {
    db = JSON.parse(fs.readFileSync(DB_FILE));
} else {
    fs.writeFileSync(DB_FILE, '{}');
}

let loginStates = {}; 

// --- ROUTES ---

// 1. REGISTER INIT
app.post('/register-init', async (req, res) => {
    try {
        const { userId, requestArray } = req.body;
        console.log(`[Register] 1. Init for: ${userId}`);

        const request = jsonToBin(requestArray);
        const userBytes = strToBytes(userId);

        const setup = ServerSetup.deserialize(SERVER_KEY_BYTES);
        const handler = new HandleRegistration(setup);
        const response = handler.start(userBytes, request);
        
        handler.free();
        setup.free();

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
        console.log(`[Register] 2. Finish for: ${userId}`);
        db[userId] = recordArray;
        fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
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
        console.log(`[Login] 1. Init for: ${userId}`);
        
        if (!db[userId]) return res.status(400).json({ error: "User not found" });

        const record = jsonToBin(db[userId]);
        const request = jsonToBin(startUploadArray);
        const userBytes = strToBytes(userId);

        const setup = ServerSetup.deserialize(SERVER_KEY_BYTES);
        const handler = new HandleLogin(setup);
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
        console.log(`[Login] 2. Finish for: ${userId}`);
        
        const clientFinish = jsonToBin(clientFinishArray);
        const stateArray = loginStates[userId];

        if (!stateArray) return res.status(400).json({ error: "No login state found" });

        // Load keys
        const setup = ServerSetup.deserialize(SERVER_KEY_BYTES);
        
        // Restore handler
        const handler = HandleLogin.deserialize(jsonToBin(stateArray), setup);
        
        // Finish (Consumes handler!)
        const sessionKey = handler.finish(clientFinish);
        
        // handler.free(); <--- DELETE THIS LINE. It causes the crash.
        
        setup.free(); // Keep this. Setup is still valid.

        console.log("✅ LOGIN SUCCESS!");
        res.json({ success: true, sessionKeyArray: binToJson(sessionKey) });
    } catch (e) {
        console.error("Login Finish Error:", e);
        res.status(401).json({ error: "Login Failed" });
    }
});

app.listen(3000, () => console.log('🚀 Server running on http://localhost:3000'));
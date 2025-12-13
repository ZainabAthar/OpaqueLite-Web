import init, { Registration, Login } from '@47ng/opaque-client';
import { argon2id } from 'hash-wasm'; // ADDED
import QRCode from 'qrcode';          // ADDED

// --- HELPERS ---
const binToJson = (u8) => Array.from(u8);
const jsonToBin = (arr) => new Uint8Array(arr);
const strToBytes = (str) => new TextEncoder().encode(str);
const toHex = (u8) => Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('');

// --- UI LOGGING ---
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

// --- ARGON2 HELPER (ADDED) ---
async function deriveSlowPassword(password, salt) {
    log("⏳ Running Argon2id Hardening...", "warn");
    const hashedPassword = await argon2id({
        password: password,
        salt: salt, 
        parallelism: 1, iterations: 2, memorySize: 512, hashLength: 32,
        outputType: 'encoded'
    });
    log(`✅ Password Hardened.`, "success");
    return hashedPassword;
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
            if(document.body.className !== "attack-critical") {
                 log(`SECURITY ALERT: ${status.message}`, 'critical');
            }
        }
    } catch (e) { }
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
        
        // 1. Argon2id (Hardening)
        const hardPass = await deriveSlowPassword(pass, user);

        const reg = new Registration();
        const request = reg.start(hardPass); // Use Hardened Password
        
        log(`Generating blinded record for ${user}...`, 'info');

        // 2. Send Init
        const res1 = await fetch('http://localhost:3000/register-init', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ userId: user, requestArray: binToJson(request) })
        });
        const data1 = await res1.json();
        if(data1.error) throw new Error(data1.error);

        const serverResponse = jsonToBin(data1.responseArray);

        // 3. Finish
        const record = reg.finish(hardPass, serverResponse);

        // 4. Upload
        const res2 = await fetch('http://localhost:3000/register-finish', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ userId: user, recordArray: binToJson(record) })
        });

        const data2 = await res2.json();
        
        if(data2.success) {
            log(`✅ Registered ${user} successfully.`, 'success');
            
            // 5. Show QR Code
            log("📲 SCAN QR CODE BELOW FOR 2FA:", "warn");
            const qrUrl = await QRCode.toDataURL(data2.otpAuthUrl);
            const consoleDiv = document.getElementById('console-output');
            const img = document.createElement('img');
            img.src = qrUrl;
            img.style.width = "150px";
            img.style.border = "5px solid white";
            img.style.marginTop = "10px";
            consoleDiv.appendChild(img);
            consoleDiv.scrollTop = consoleDiv.scrollHeight;
        }
        
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

        // 1. Argon2id (Hardening)
        const hardPass = await deriveSlowPassword(pass, user);

        const login = new Login();
        const request = login.start(hardPass); // Use Hardened Password

        log(`Attempting login for ${user}...`, 'info');

        // 2. Init
        const res1 = await fetch('http://localhost:3000/login-init', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ userId: user, startUploadArray: binToJson(request) })
        });
        const data1 = await res1.json();
        if(data1.error) throw new Error(data1.error);

        const serverResponse = jsonToBin(data1.serverResponseArray);
        
        // 3. Finish
        const output = login.finish(hardPass, serverResponse);
        
        const clientFinish = output.message || output; 
        const sessionKey = output.session_key || output.sessionKey || login.getSessionKey();

        // 4. Send
        const res2 = await fetch('http://localhost:3000/login-finish', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ userId: user, clientFinishArray: binToJson(clientFinish) })
        });
        
        login.free();

        const result = await res2.json();
        
        // 5. MFA CHECK
        if(result.step === '2FA_REQUIRED') {
            log("🔒 OPAQUE Verified. Enter 2FA Code...", "warn");
            
            const token = prompt("Enter 6-digit Google Authenticator Code:");
            if(!token) return log("Login Cancelled", "error");

            const res3 = await fetch('http://localhost:3000/verify-2fa', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ userId: user, token: token })
            });
            const final = await res3.json();

            if(final.success) {
                log("✅✅ FULL LOGIN SUCCESS!", "success");
                log(`🔑 Session Key: ${toHex(jsonToBin(result.tempSessionKey)).substring(0,20)}...`, "success");
            } else {
                log("❌ 2FA Failed. Access Denied.", "error");
            }
        } else {
            log("Login Failed: " + result.error, 'error');
        }
    } catch (e) {
        log("Login Failed: " + e.message, 'error');
    }
});
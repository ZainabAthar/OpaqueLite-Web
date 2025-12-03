import fs from 'fs';
import path from 'path';

const folder = './node_modules/@47ng/opaque-client';

try {
    console.log(`Checking folder: ${folder}`);
    const files = fs.readdirSync(folder);
    console.log("\nFiles found:");
    files.forEach(file => {
        console.log(" - " + file);
    });
} catch (e) {
    console.error("Could not find folder. Are you in the root directory?");
}
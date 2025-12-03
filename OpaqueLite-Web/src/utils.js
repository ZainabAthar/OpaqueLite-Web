// src/utils.js
export const toHex = (u8) => Buffer.from(u8).toString('hex');
export const fromHex = (str) => Uint8Array.from(Buffer.from(str, 'hex'));
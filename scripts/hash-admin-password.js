import { webcrypto } from 'node:crypto';
import readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';

const rl = readline.createInterface({ input, output });
const password = await rl.question('Admin password: ');
rl.close();
if (password.length < 12) throw new Error('Use an admin password of at least 12 characters.');
const salt = webcrypto.getRandomValues(new Uint8Array(16));
const key = await webcrypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
const bits = await webcrypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 120000, hash: 'SHA-256' }, key, 256);
const hex = a => [...new Uint8Array(a)].map(b => b.toString(16).padStart(2, '0')).join('');
console.log(`pbkdf2$120000$${hex(salt)}$${hex(bits)}`);

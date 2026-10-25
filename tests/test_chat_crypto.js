const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');

const projectRoot = path.resolve(__dirname, '..');
const source = fs.readFileSync(
    path.join(projectRoot, 'e2ee_chat', 'static', 'app.js'),
    'utf8'
);
const elements = new Map();
const document = {
    getElementById(id) {
        if (!elements.has(id)) {
            elements.set(id, {
                addEventListener() {},
                style: { display: 'none' },
                classList: { add() {}, remove() {} }
            });
        }
        return elements.get(id);
    },
    createElement() {
        return {
            style: {},
            appendChild() {},
            append() {},
            classList: { add() {}, remove() {} }
        };
    },
    createTextNode(text) {
        return { textContent: text };
    },
    querySelectorAll() {
        return [];
    }
};
const context = vm.createContext({
    document,
    crypto: webcrypto,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    ArrayBuffer,
    btoa,
    atob,
    Blob,
    URL,
    console
});

vm.runInContext(
    `${source}\nglobalThis.chatCryptoTests = { encryptPayload, decryptPayload, bytesToBase64, base64ToBytes, setPrivateKey: (privateKey) => { keyPair = { privateKey }; } };`,
    context
);

test('AES-GCM and RSA-OAEP round-trip text and binary payloads', async () => {
    const { chatCryptoTests } = context;
    const pair = await webcrypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
        },
        false,
        ['encrypt', 'decrypt']
    );
    const publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
    chatCryptoTests.setPrivateKey(pair.privateKey);

    for (const original of [
        new TextEncoder().encode('hello encrypted world'),
        new Uint8Array([0, 1, 127, 128, 254, 255])
    ]) {
        const encrypted = await chatCryptoTests.encryptPayload(original, publicJwk);
        const decrypted = await chatCryptoTests.decryptPayload(
            encrypted.ciphertext,
            encrypted.iv,
            encrypted.encryptedKey
        );
        assert.deepEqual(Array.from(decrypted), Array.from(original));
    }
});

test('AES-GCM rejects modified ciphertext', async () => {
    const { chatCryptoTests } = context;
    const pair = await webcrypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
        },
        false,
        ['encrypt', 'decrypt']
    );
    const publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
    chatCryptoTests.setPrivateKey(pair.privateKey);

    const encrypted = await chatCryptoTests.encryptPayload(
        new TextEncoder().encode('must detect tampering'),
        publicJwk
    );
    const bytes = chatCryptoTests.base64ToBytes(encrypted.ciphertext);
    bytes[0] ^= 1;
    const modified = chatCryptoTests.bytesToBase64(bytes);

    await assert.rejects(
        chatCryptoTests.decryptPayload(modified, encrypted.iv, encrypted.encryptedKey)
    );
});

let socket;
let keyPair;
let myUsername;
let selectedUser = null;
let users = [];

const MAX_FILE_BYTES = 10 * 1024 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

document.getElementById('generateKeysBtn').addEventListener('click', generateKeys);
document.getElementById('registerBtn').addEventListener('click', register);
document.getElementById('sendBtn').addEventListener('click', sendMessage);
document.getElementById('sendFileBtn').addEventListener('click', sendFile);
document.getElementById('messageInput').addEventListener('keypress', (event) => {
    if (event.key === 'Enter') sendMessage();
});

async function generateKeys() {
    const button = document.getElementById('generateKeysBtn');
    const status = document.getElementById('keyStatus');
    button.disabled = true;
    status.textContent = 'Generating RSA-OAEP-2048 keys...';
    status.className = 'status';

    try {
        keyPair = await crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256'
            },
            false,
            ['encrypt', 'decrypt']
        );
        status.textContent = 'Keys generated in this browser session.';
        status.className = 'status success';
        document.getElementById('registerBtn').disabled = false;
    } catch (error) {
        keyPair = null;
        button.disabled = false;
        status.textContent = `Key generation failed: ${error.message}`;
        status.className = 'status error';
    }
}

function register() {
    myUsername = document.getElementById('username').value.trim();
    if (myUsername.length < 2 || myUsername.length > 32) {
        showStatus('Choose a username between 2 and 32 characters.');
        return;
    }
    if (!keyPair) {
        showStatus('Generate encryption keys before connecting.');
        return;
    }

    document.getElementById('registerBtn').disabled = true;
    socket = io();
    socket.on('connect', async () => {
        try {
            const publicKey = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
            socket.emit('register', {
                user_id: crypto.randomUUID(),
                display_name: myUsername,
                public_key: publicKey
            });
        } catch (error) {
            showStatus(`Could not register: ${error.message}`);
        }
    });
    socket.on('user_registered', (result) => {
        if (!result || !result.success) {
            showStatus(result?.error || 'Registration failed.');
            document.getElementById('registerBtn').disabled = false;
            return;
        }
        document.getElementById('setupPanel').style.display = 'none';
        document.getElementById('chatPanel').style.display = 'flex';
        document.getElementById('myUsername').textContent = myUsername;
    });
    socket.on('user_list', (userList) => {
        users = userList.filter((user) => user.sid !== socket.id);
        updateUserList();
    });
    socket.on('receive_message', async (data) => {
        try {
            const bytes = await decryptPayload(
                data.encrypted_message,
                data.iv,
                data.encrypted_key
            );
            displayMessage(data.from_user, decoder.decode(bytes), 'received');
        } catch (error) {
            displayMessage(data.from_user || 'Unknown sender', '[Message authentication/decryption failed]', 'received');
        }
    });
    socket.on('receive_file', async (data) => {
        try {
            const bytes = await decryptPayload(data.encrypted_file, data.iv, data.encrypted_key);
            displayFile(data.from_user || 'Unknown sender', bytes, data.filename, data.file_type, 'received');
        } catch (error) {
            displayMessage(data.from_user || 'Unknown sender', '[File authentication/decryption failed]', 'received');
        }
    });
    socket.on('message_sent', (result) => {
        if (result?.status !== 'delivered') showStatus(result?.error || 'Message was not delivered.');
    });
    socket.on('file_sent', (result) => {
        if (result?.status !== 'delivered') showStatus(result?.error || 'File was not delivered.');
    });
    socket.on('connect_error', (error) => {
        showStatus(`Could not connect to the chat server: ${error.message}`);
        document.getElementById('registerBtn').disabled = false;
    });
}

function updateUserList() {
    const userListDiv = document.getElementById('userList');
    userListDiv.replaceChildren();

    users.forEach((user) => {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'user-item';
        item.textContent = user.display_name;
        item.addEventListener('click', () => selectUser(user, item));
        userListDiv.appendChild(item);
    });
}

function selectUser(user, item) {
    document.querySelectorAll('.user-item').forEach((element) => element.classList.remove('active'));
    item.classList.add('active');
    selectedUser = user;
    document.getElementById('chatWith').textContent = `Chatting with: ${user.display_name}`;
    document.getElementById('messageInput').disabled = false;
    document.getElementById('sendBtn').disabled = false;
    document.getElementById('fileInput').disabled = false;
    document.getElementById('sendFileBtn').disabled = false;
}

async function encryptPayload(data, recipientPublicJwk) {
    const recipientKey = await crypto.subtle.importKey(
        'jwk',
        recipientPublicJwk,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt']
    );
    const aesKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
    const rawAesKey = await crypto.subtle.exportKey('raw', aesKey);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, data);
    const encryptedKey = await crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        recipientKey,
        rawAesKey
    );
    return {
        ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
        encryptedKey: bytesToBase64(new Uint8Array(encryptedKey)),
        iv: bytesToBase64(iv)
    };
}

async function decryptPayload(ciphertext, iv, encryptedKey) {
    if (!keyPair || !ciphertext || !iv || !encryptedKey) {
        throw new Error('Encrypted payload is incomplete.');
    }
    const rawAesKey = await crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        keyPair.privateKey,
        base64ToBytes(encryptedKey)
    );
    const aesKey = await crypto.subtle.importKey(
        'raw',
        rawAesKey,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );
    const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: base64ToBytes(iv) },
        aesKey,
        base64ToBytes(ciphertext)
    );
    return new Uint8Array(plaintext);
}

async function sendMessage() {
    const input = document.getElementById('messageInput');
    const message = input.value.trim();
    if (!message || !selectedUser) return;

    try {
        const encrypted = await encryptPayload(encoder.encode(message), selectedUser.public_key);
        socket.emit('send_message', {
            recipient_sid: selectedUser.sid,
            encrypted_message: encrypted.ciphertext,
            encrypted_key: encrypted.encryptedKey,
            iv: encrypted.iv,
            message_type: 'text'
        });
        displayMessage('You', message, 'sent');
        input.value = '';
    } catch (error) {
        showStatus(`Message encryption failed: ${error.message}`);
    }
}

async function sendFile() {
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    if (!file || !selectedUser) return;
    if (file.size > MAX_FILE_BYTES) {
        showStatus('Files must be 10 MiB or smaller.');
        return;
    }

    try {
        const encrypted = await encryptPayload(
            new Uint8Array(await file.arrayBuffer()),
            selectedUser.public_key
        );
        socket.emit('send_file', {
            recipient_sid: selectedUser.sid,
            encrypted_file: encrypted.ciphertext,
            encrypted_key: encrypted.encryptedKey,
            iv: encrypted.iv,
            filename: file.name,
            file_type: file.type || 'application/octet-stream'
        });
        displayMessage('You', `[File: ${file.name}]`, 'sent');
        fileInput.value = '';
    } catch (error) {
        showStatus(`File encryption failed: ${error.message}`);
    }
}

function displayMessage(sender, message, type) {
    const item = document.createElement('div');
    item.className = `message ${type}`;
    const senderLabel = document.createElement('div');
    senderLabel.className = 'message-info';
    senderLabel.textContent = sender;
    item.append(senderLabel, document.createTextNode(message));
    appendMessage(item);
}

function displayFile(sender, bytes, filename, fileType, type) {
    const item = document.createElement('div');
    item.className = `message ${type}`;
    const senderLabel = document.createElement('div');
    senderLabel.className = 'message-info';
    senderLabel.textContent = sender;
    item.appendChild(senderLabel);

    const safeType = typeof fileType === 'string' ? fileType : 'application/octet-stream';
    const fileUrl = URL.createObjectURL(new Blob([bytes], { type: safeType }));
    if (safeType.startsWith('image/')) {
        const image = document.createElement('img');
        image.src = fileUrl;
        image.alt = filename;
        image.style.maxWidth = '200px';
        image.style.maxHeight = '200px';
        item.appendChild(image);
    }
    const link = document.createElement('a');
    link.href = fileUrl;
    link.download = filename || 'download';
    link.textContent = `Download ${filename || 'file'}`;
    item.appendChild(link);
    appendMessage(item);
}

function appendMessage(item) {
    const messages = document.getElementById('messages');
    messages.appendChild(item);
    messages.scrollTop = messages.scrollHeight;
}

function bytesToBase64(bytes) {
    let binary = '';
    const chunkSize = 0x8000;
    for (let index = 0; index < bytes.length; index += chunkSize) {
        binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
    }
    return btoa(binary);
}

function base64ToBytes(value) {
    const binary = atob(value);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function showStatus(message) {
    const chatPanel = document.getElementById('chatPanel');
    const status = chatPanel.style.display === 'none'
        ? document.getElementById('keyStatus')
        : document.getElementById('chatStatus');
    status.textContent = message;
    status.className = 'status error';
}

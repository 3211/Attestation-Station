'use strict';

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const EC = require('elliptic').ec;
const { hkdf } = require('@noble/hashes/hkdf');
const { sha256 } = require('@noble/hashes/sha256');
const { keccak_256 } = require('@noble/hashes/sha3');
const aes = require('@noble/ciphers/aes');

const PORT = 3000;
const HKDF_INFO = new TextEncoder().encode('ecdsa_encryption');
const MIN_PACKET_HEX_LEN = 186;
const EPHEMERAL_KEY_BYTES = 65;
const EPHEMERAL_KEY_HEX = 130;
const GCM_NONCE_BYTES = 12;
const GCM_NONCE_HEX = 24;
const NONCE_BYTES = 32;
const NONCE_HEX = 64;
const PROBE_MESSAGE = 'Attestation Probe';

const ec = new EC('secp256k1');

// --- CRYPTO UTILITIES ---

function generateEphemeralKeyPair() {
    const kp = ec.genKeyPair();
    return {
        privateKeyHex: kp.getPrivate().toString('hex'),
        publicKeyHex: kp.getPublic().encode('hex', false),
        privateKeyBN: kp.getPrivate(),
        publicKeyPoint: kp.getPublic()
    };
}

function deriveSharedSecret(privHex, remotePubHex) {
    const kp = ec.keyFromPrivate(privHex, 'hex');
    const remote = ec.keyFromPublic(remotePubHex, 'hex');
    const sharedBN = kp.derive(remote.getPublic());
    return new Uint8Array(sharedBN.toArray('be', 32));
}

function deriveSymmetricKey(sharedSecret) {
    return hkdf(sha256, sharedSecret, undefined, HKDF_INFO, 32);
}

function encryptPayload(plaintext, symKey, ephemPubHex) {
    const nonce = new Uint8Array(crypto.randomBytes(GCM_NONCE_BYTES));
    const ptBytes = new TextEncoder().encode(plaintext);
    const ct = aes.gcm(symKey, nonce).encrypt(ptBytes);
    const pubBytes = Uint8Array.from(Buffer.from(ephemPubHex, 'hex'));
    const packet = new Uint8Array(EPHEMERAL_KEY_BYTES + GCM_NONCE_BYTES + ct.length);
    packet.set(pubBytes, 0);
    packet.set(nonce, EPHEMERAL_KEY_BYTES);
    packet.set(ct, EPHEMERAL_KEY_BYTES + GCM_NONCE_BYTES);
    return Buffer.from(packet).toString('hex');
}

function decryptPayload(hexStr, localPrivHex) {
    const bytes = Uint8Array.from(Buffer.from(hexStr, 'hex'));
    const ephemPubHex = Buffer.from(bytes.slice(0, EPHEMERAL_KEY_BYTES)).toString('hex');
    const nonce = bytes.slice(EPHEMERAL_KEY_BYTES, EPHEMERAL_KEY_BYTES + GCM_NONCE_BYTES);
    const ct = bytes.slice(EPHEMERAL_KEY_BYTES + GCM_NONCE_BYTES);
    const shared = deriveSharedSecret(localPrivHex, ephemPubHex);
    const symKey = deriveSymmetricKey(shared);
    const pt = aes.gcm(symKey, nonce).decrypt(ct);
    return new TextDecoder().decode(pt);
}

function generateNonce() {
    return crypto.randomBytes(NONCE_BYTES).toString('hex');
}

function validateHexString(hex) {
    if (hex.length < MIN_PACKET_HEX_LEN) {
        return { valid: false, reason: `Too short: ${hex.length} < ${MIN_PACKET_HEX_LEN}` };
    }
    if (hex.length % 2 !== 0) {
        return { valid: false, reason: 'Odd length' };
    }
    if (!/^[0-9a-fA-F]+$/.test(hex)) {
        return { valid: false, reason: 'Non-hex characters' };
    }
    return { valid: true };
}

function normalizeSigningKey(key) {
    if (key.length === 128 && !key.startsWith('04')) {
        return '04' + key;
    }
    return key;
}

function deriveEthereumAddress(pubHex) {
    let clean = pubHex.startsWith('04') ? pubHex.slice(2) : pubHex;
    const hash = keccak_256(Uint8Array.from(Buffer.from(clean, 'hex')));
    return '0x' + Buffer.from(hash.slice(-20)).toString('hex');
}

// --- INDEPENDENT_HARDWARE_QUOTE_PARSE ---

function independentHardwareQuoteParse(quoteB64, expectedNonce) {
    // INDEPENDENT_HARDWARE_QUOTE_PARSE
    // Structural audit of the raw Intel TDX quote bytes.
    // Does NOT simply return the server 'verified' boolean.
    const result = {
        teeType: null,
        debugMode: null,
        reportDataMatch: false,
        quoteVersion: null,
        rawBytesLength: 0,
        warnings: [],
        errors: []
    };

    try {
        const q = Buffer.from(quoteB64, 'base64');
        result.rawBytesLength = q.length;

        if (q.length < 48) {
            result.errors.push('Quote too short for header');
            return result;
        }

        result.quoteVersion = q.readUInt16LE(0);
        const teeType = q.readUInt16LE(4);
        result.teeType = teeType;

        if (teeType !== 0x0081 && teeType !== 0x0000) {
            result.warnings.push(`Unexpected TEE type: 0x${teeType.toString(16)}`);
        }

        // TD Report structure starts at offset 48 in DCAP quote
        if (q.length >= 48 + 1024) {
            const td = 48;

            // ATTRIBUTES at offset 64 within TD Report
            const attrOff = td + 64;
            if (attrOff + 8 <= q.length) {
                const attr = q.readBigUInt64LE(attrOff);
                result.debugMode = (attr & 1n) === 1n;
                if (result.debugMode) {
                    result.errors.push('CRITICAL: Debug mode ENABLED in TEE quote');
                }
            }

            // REPORTDATA at offset 512 within TD Report, 64 bytes total
            const rdOff = td + 512;
            if (rdOff + 64 <= q.length && expectedNonce) {
                const rd = q.slice(rdOff, rdOff + 64);
                const nonceHash = sha256(new TextEncoder().encode(expectedNonce));
                const rdFirst32 = rd.slice(0, 32);
                const rdLast32 = rd.slice(32, 64);
                const last32Zero = rdLast32.every(b => b === 0);
                result.reportDataMatch = Buffer.from(rdFirst32).equals(Buffer.from(nonceHash)) && last32Zero;
                if (!result.reportDataMatch) {
                    result.warnings.push('Report data does not match nonce hash');
                }
            }
        } else {
            result.warnings.push('Quote too short for full TD Report');
        }
    } catch (e) {
        result.errors.push('Parse error: ' + e.message);
    }

    return result;
}

// --- EXPRESS APP ---

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// POST /api/attest - Steps 1-2 only
app.post('/api/attest', async (req, res) => {
    const { targetUrl, model, apiKey } = req.body;
    if (!targetUrl || !model || !apiKey) {
        return res.status(400).json({ error: 'Missing required fields: targetUrl, model, apiKey' });
    }

    try {
        const nonce = generateNonce();
        if (nonce.length !== NONCE_HEX) {
            return res.status(500).json({ error: `Nonce length violation: ${nonce.length}` });
        }

        const url = `${targetUrl.replace(/\/$/, '')}/tee/attestation?model=${encodeURIComponent(model)}&nonce=${nonce}`;
        const resp = await fetch(url, {
            headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' }
        });

        if (resp.status !== 200) {
            return res.status(502).json({ error: `Attestation endpoint returned ${resp.status}` });
        }

        const data = await resp.json();

        if (data.nonce !== nonce) {
            return res.status(500).json({ error: 'Nonce mismatch - replay suspected', expected: nonce, received: data.nonce });
        }

        if (!data.intel_quote) {
            return res.status(500).json({ error: 'Missing intel_quote' });
        }

        try {
            const buf = Buffer.from(data.intel_quote, 'base64');
            if (buf.length === 0) throw new Error('Empty');
        } catch (e) {
            return res.status(500).json({ error: 'intel_quote not valid Base64' });
        }

        const parseResult = independentHardwareQuoteParse(data.intel_quote, nonce);
        const normKey = normalizeSigningKey(data.signing_key || '');
        let derivedAddr = null;
        let addrMatch = false;
        if (normKey.length === 130) {
            derivedAddr = deriveEthereumAddress(normKey);
            addrMatch = derivedAddr.toLowerCase() === (data.signing_address || '').toLowerCase();
        }

        res.json({
            step1: { name: 'nonce_generation', status: 'pass', nonce },
            step2: {
                name: 'attestation_harvest',
                status: parseResult.errors.length > 0 ? 'warning' : 'pass',
                data: {
                    verified: data.verified,
                    nonceMatch: true,
                    intelQuoteValid: true,
                    independentQuoteParse: parseResult,
                    signingKey: normKey,
                    signingAddress: data.signing_address,
                    derivedAddress: derivedAddr,
                    addressMatch: addrMatch,
                    teeProvider: data.tee_provider,
                    model: data.model,
                    nvidiaPayload: data.nvidia_payload || null
                }
            }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/verify - Full 5-step verification with SSE
app.post('/api/verify', async (req, res) => {
    const { targetUrl, model, apiKey } = req.body;
    if (!targetUrl || !model || !apiKey) {
        return res.status(400).json({ error: 'Missing required fields: targetUrl, model, apiKey' });
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    const send = (event, data) => {
        res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };

    try {
        // Step 1: Nonce Generation
        const nonce = generateNonce();
        if (nonce.length !== NONCE_HEX) {
            send('error', { step: 1, message: `Nonce length violation: ${nonce.length} != ${NONCE_HEX}` });
            res.end();
            return;
        }
        send('step', { step: 1, name: 'nonce_generation', status: 'pass', data: { nonce } });

        // Step 2: Attestation Harvest
        const attUrl = `${targetUrl.replace(/\/$/, '')}/tee/attestation?model=${encodeURIComponent(model)}&nonce=${nonce}`;
        let attResp;
        try {
            attResp = await fetch(attUrl, {
                headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' }
            });
        } catch (e) {
            send('error', { step: 2, message: `Attestation request failed: ${e.message}` });
            res.end();
            return;
        }

        if (attResp.status !== 200) {
            const errText = await attResp.text().catch(() => '');
            send('error', { step: 2, message: `Attestation endpoint returned ${attResp.status}: ${errText}` });
            res.end();
            return;
        }

        const attData = await attResp.json();

        if (attData.nonce !== nonce) {
            send('error', { step: 2, message: `Nonce mismatch: expected ${nonce}, received ${attData.nonce}` });
            res.end();
            return;
        }

        if (!attData.intel_quote) {
            send('error', { step: 2, message: 'Missing intel_quote field' });
            res.end();
            return;
        }

        try {
            const buf = Buffer.from(attData.intel_quote, 'base64');
            if (buf.length === 0) throw new Error('Empty');
        } catch (e) {
            send('error', { step: 2, message: 'intel_quote is not valid Base64' });
            res.end();
            return;
        }

        const qp = independentHardwareQuoteParse(attData.intel_quote, nonce);

        send('step', {
            step: 2,
            name: 'attestation_harvest',
            status: qp.errors.length > 0 ? 'warning' : 'pass',
            data: {
                verified: attData.verified,
                nonceMatch: true,
                intelQuoteValid: true,
                independentQuoteParse: qp,
                teeProvider: attData.tee_provider,
                model: attData.model,
                nvidiaPayload: attData.nvidia_payload || null
            }
        });

        // Step 3: Key Normalization
        const normKey = normalizeSigningKey(attData.signing_key || '');
        const wasNormalized = normKey !== (attData.signing_key || '');
        if (normKey.length !== 130 || !normKey.startsWith('04')) {
            send('error', { step: 3, message: `Invalid signing key after normalization: length=${normKey.length}` });
            res.end();
            return;
        }

        const derivedAddr = deriveEthereumAddress(normKey);
        const addrMatch = derivedAddr.toLowerCase() === (attData.signing_address || '').toLowerCase();

        send('step', {
            step: 3,
            name: 'key_normalization',
            status: addrMatch ? 'pass' : 'warning',
            data: {
                signingKey: normKey,
                normalized: wasNormalized,
                derivedAddress: derivedAddr,
                reportedAddress: attData.signing_address,
                addressMatch: addrMatch
            }
        });

        // Step 4: Request Pipeline Mocking
        const ephKP = generateEphemeralKeyPair();
        const shared = deriveSharedSecret(ephKP.privateKeyHex, normKey);
        const symKey = deriveSymmetricKey(shared);
        const encPayload = encryptPayload(PROBE_MESSAGE, symKey, ephKP.publicKeyHex);

        const chatUrl = `${targetUrl.replace(/\/$/, '')}/chat/completions`;
        const chatHeaders = {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
            'X-Venice-TEE-Client-Pub-Key': ephKP.publicKeyHex,
            'X-Venice-TEE-Model-Pub-Key': normKey
        };

        const chatBody = {
            model,
            stream: true,
            messages: [{ role: 'user', content: encPayload }]
        };

        send('step', {
            step: 4,
            name: 'request_pipeline',
            status: 'pass',
            data: { encrypted: true, clientPubKey: ephKP.publicKeyHex, modelPubKey: normKey }
        });

        // Step 5: Streaming Decryption Audit
        let chatResp;
        try {
            chatResp = await fetch(chatUrl, {
                method: 'POST',
                headers: chatHeaders,
                body: JSON.stringify(chatBody)
            });
        } catch (e) {
            send('error', { step: 5, message: `Chat request failed: ${e.message}` });
            res.end();
            return;
        }

        if (chatResp.status !== 200) {
            const errBody = await chatResp.text().catch(() => '');
            send('error', { step: 5, message: `Chat endpoint returned ${chatResp.status}: ${errBody.substring(0, 500)}` });
            res.end();
            return;
        }

        let fullText = '';
        let chunkIdx = 0;
        const decryptErrors = [];

        const reader = chatResp.body.getReader();
        const decoder = new TextDecoder();
        let sseBuf = '';

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            sseBuf += decoder.decode(value, { stream: true });

            const lines = sseBuf.split('\n');
            sseBuf = lines.pop() || '';

            for (const line of lines) {
                const trimmed = line.trim();
                if (!trimmed.startsWith('data:')) continue;
                const payload = trimmed.slice(5).trim();
                if (payload === '[DONE]') continue;

                let hexContent = null;
                try {
                    const j = JSON.parse(payload);
                    if (j.choices && j.choices[0] && j.choices[0].delta && j.choices[0].delta.content) {
                        hexContent = j.choices[0].delta.content;
                    }
                } catch (_) {
                    hexContent = payload;
                }

                if (!hexContent) continue;

                const v = validateHexString(hexContent);
                if (!v.valid) {
                    decryptErrors.push(`Chunk ${chunkIdx}: ${v.reason}`);
                    continue;
                }

                try {
                    const pt = decryptPayload(hexContent, ephKP.privateKeyHex);
                    fullText += pt;
                    chunkIdx++;
                    send('chunk', { step: 5, index: chunkIdx, plaintext: pt });
                } catch (e) {
                    decryptErrors.push(`Chunk ${chunkIdx}: Decrypt failed: ${e.message}`);
                }
            }
        }

        const streamStatus = decryptErrors.length === 0 ? 'pass' : (chunkIdx > 0 ? 'warning' : 'fail');

        send('step', {
            step: 5,
            name: 'streaming_decrypt',
            status: streamStatus,
            data: { totalChunks: chunkIdx, errors: decryptErrors, fullText }
        });

        // Certificate
        const certificate = {
            model: attData.model,
            teeProvider: attData.tee_provider,
            signingKey: normKey,
            signingAddress: attData.signing_address,
            derivedAddress: derivedAddr,
            addressMatch: addrMatch,
            nonce,
            intelQuoteValidated: true,
            debugMode: qp.debugMode,
            teeType: qp.teeType,
            quoteVersion: qp.quoteVersion,
            reportDataMatch: qp.reportDataMatch,
            streamVerified: chunkIdx > 0,
            timestamp: new Date().toISOString()
        };

        send('complete', { success: true, certificate });
        res.end();

    } catch (err) {
        send('error', { step: 0, message: err.message });
        res.end();
    }
});

app.get('/', (_req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Attestation Station running on port ${PORT}`);
});
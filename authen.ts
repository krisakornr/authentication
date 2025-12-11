import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

// SDMFileReadKey (16 bytes) – you said it is AD repeated 16 times
// Hex representation: "ADADAD...AD" (32 hex chars)
const K_SDM_HEX = "AD".repeat(16);

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Hex string must have even length");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

function xorBlock(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) {
    throw new Error("xorBlock: length mismatch");
  }
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

// Left shift a 16-byte block by 1 bit (for CMAC subkey generation)
function leftShiftOneBit(input: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  let carry = 0;
  for (let i = 15; i >= 0; i--) {
    const b = input[i];
    out[i] = ((b << 1) & 0xff) | carry;
    carry = (b & 0x80) ? 1 : 0;
  }
  return out;
}

// Generate CMAC subkeys K1, K2 (NIST SP 800-38B), using AES-128 cipher core
async function generateSubkeys(keyBytes: Uint8Array): Promise<{
  K1: Uint8Array;
  K2: Uint8Array;
}> {
  const zeroBlock = new Uint8Array(16); // 0^128

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-CBC" },
    false,
    ["encrypt"],
  );

  const iv = new Uint8Array(16); // all zeros
  const enc = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-CBC", iv },
      cryptoKey,
      zeroBlock,
    ) as ArrayBuffer,
  );

  // First 16 bytes are AES-ECB(K, 0^128) since IV=0 and only one block
  const L = enc.slice(0, 16);

  const Rb = 0x87;

  // K1
  let K1 = leftShiftOneBit(L);
  if (L[0] & 0x80) {
    K1[15] ^= Rb;
  }

  // K2
  let K2 = leftShiftOneBit(K1);
  if (K1[0] & 0x80) {
    K2[15] ^= Rb;
  }

  return { K1, K2 };
}

// AES-128-CMAC using WebCrypto AES-CBC as the underlying block cipher.
// Supports arbitrary message length (0 or more bytes).
async function aesCmac(keyBytes: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const { K1, K2 } = await generateSubkeys(keyBytes);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-CBC" },
    false,
    ["encrypt"],
  );

  const blockSize = 16;
  const n = message.length === 0
    ? 1
    : Math.ceil(message.length / blockSize);

  const isComplete = message.length > 0 && (message.length % blockSize === 0);

  let lastBlock = new Uint8Array(blockSize);

  if (message.length === 0) {
    // Zero-length message: M1* = 0^128, use K2
    lastBlock = xorBlock(lastBlock, K2);
  } else {
    const start = (n - 1) * blockSize;
    const end = message.length;
    const M_last = message.slice(start, end);

    if (isComplete) {
      // Complete last block → XOR with K1
      lastBlock = xorBlock(M_last, K1);
    } else {
      // Incomplete last block → pad, then XOR with K2
      const padded = new Uint8Array(blockSize);
      padded.set(M_last, 0);
      padded[M_last.length] = 0x80;
      // rest already zeros
      lastBlock = xorBlock(padded, K2);
    }
  }

  let X = new Uint8Array(blockSize); // X_0 = 0^128
  const ivZero = new Uint8Array(blockSize);

  // Process all blocks except the last one
  const numFullBlocks = message.length === 0 ? 0 : (n - 1);
  for (let i = 0; i < numFullBlocks; i++) {
    const block = message.slice(i * blockSize, (i + 1) * blockSize);
    const Y = xorBlock(X, block);

    const enc = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-CBC", iv: ivZero },
        cryptoKey,
        Y,
      ) as ArrayBuffer,
    );
    X = enc.slice(0, blockSize);
  }

  // Final block
  const Y_last = xorBlock(X, lastBlock);
  const encLast = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-CBC", iv: ivZero },
      cryptoKey,
      Y_last,
    ) as ArrayBuffer,
  );
  const T = encLast.slice(0, blockSize); // full 16-byte CMAC

  return T;
}

// Truncate CMAC to 8 bytes (16 hex chars) as per NXP MFCMAC example:
// Take every odd-indexed byte from CMAC (S1, S3, ..., S15) in MSB-first order.
function truncateMac(cmacFull: Uint8Array): string {
  if (cmacFull.length !== 16) {
    throw new Error("CMAC must be 16 bytes");
  }
  const out = new Uint8Array(8);
  let j = 0;
  for (let i = 0; i < 16; i++) {
    if (i % 2 === 1) {
      out[j++] = cmacFull[i];
    }
  }
  return bytesToHex(out);
}

// Build SV2 for Session MAC key, according to AN12196 Table 2:
// SV2 = 3CC3 0001 0080 [UID (7B MSB)] [SDMReadCtr (3B LSB)]
function buildSV2(uid: Uint8Array, cntDec: string): Uint8Array {
  if (uid.length !== 7) {
    throw new Error("UID must be 7 bytes");
  }
  const ctrInt = parseInt(cntDec, 10);
  if (!Number.isFinite(ctrInt) || ctrInt < 0 || ctrInt > 0xFFFFFF) {
    throw new Error("Counter out of range (0..16777215)");
  }

  const ctr = new Uint8Array(3);
  // LSB first for SDMReadCtr
  ctr[0] = ctrInt & 0xff;
  ctr[1] = (ctrInt >> 8) & 0xff;
  ctr[2] = (ctrInt >> 16) & 0xff;

  const sv2 = new Uint8Array(16);
  sv2.set([0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80], 0); // 6 bytes
  sv2.set(uid, 6);          // positions 6..12 (7 bytes)
  sv2.set(ctr, 13);         // positions 13..15 (3 bytes)

  return sv2;
}

// Compute expected SUN signature (SDMMAC) for given id & cnt
// idHex: 14 hex chars (7-byte UID MSB)
// cnt:   6-digit decimal string (e.g. "000001")
async function computeExpectedSig(idHex: string, cnt: string): Promise<string> {
  if (!/^[0-9A-Fa-f]{14}$/.test(idHex)) {
    throw new Error("id must be 14 hex characters (7-byte UID).");
  }
  if (!/^\d{6}$/.test(cnt)) {
    throw new Error("cnt must be a 6-digit decimal string, e.g. 000001.");
  }

  const uid = hexToBytes(idHex);
  const sv2 = buildSV2(uid, cnt);

  const K_SDM = hexToBytes(K_SDM_HEX);

  // 1) Session MAC key: KSesSDMFileReadMAC = CMAC(KSDMFileRead; SV2)
  const kSesMac = await aesCmac(K_SDM, sv2);

  // 2) CMAC over zero-length input using KSesSDMFileReadMAC
  const cmacFull = await aesCmac(kSesMac, new Uint8Array([]));

  // 3) Truncate to 8 bytes (16 hex chars)
  const sig = truncateMac(cmacFull);

  return sig;
}

// -----------------------------------------------------------------------------
// HTTP handler
// -----------------------------------------------------------------------------

serve(async (req) => {
  const url = new URL(req.url);
  const id = url.searchParams.get("id") ?? "";
  const cnt = url.searchParams.get("cnt") ?? "";
  const sig = (url.searchParams.get("sig") ?? "").toUpperCase();

  if (!id || !cnt || !sig) {
    return new Response(
      "Missing parameters. Expected: ?id=<14-hex>&cnt=<000001>&sig=<16-hex>",
      { status: 400 },
    );
  }

  try {
    const expected = await computeExpectedSig(id, cnt);
    const valid = expected === sig;

    const body = {
      valid,
      id,
      cnt,
      expected,
      received: sig,
    };

    return new Response(JSON.stringify(body, null, 2), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  } catch (err) {
    return new Response(`Error: ${(err as Error).message}`, { status: 400 });
  }
});

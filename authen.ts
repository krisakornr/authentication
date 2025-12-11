import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

// MODE: "json" → return JSON validation result
//       "redirect" → HTTP redirect to valid/invalid URLs below
const MODE: "json" | "redirect" = "redirect"; // change to "redirect" when needed

const API_VERSION = "sun-424-v6";

// SDMFileReadKey (Key0) – 16 bytes, AD repeated 16 times
const K_SDM_HEX = "AD".repeat(16);

// Redirect targets (used only when MODE === "redirect")
const VALID_REDIRECT_URL = "https://d.atma.to/pharmademo/PCJW8NWE63";
const INVALID_REDIRECT_URL = "https://d.atma.to/pharmademo/GVDM4H9JE8";

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

// Generate CMAC subkeys K1, K2 (NIST SP 800-38B) using AES-128 cipher core
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

  // First 16 bytes are effectively AES-ECB(K, 0^128)
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

// AES-128-CMAC using WebCrypto AES-CBC as core.
// Zero-length message is treated as an INCOMPLETE block with 0x80 padding.
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
    // Zero-length: treat as incomplete block "0x80 00..00", then XOR with K2
    const padded = new Uint8Array(blockSize);
    padded[0] = 0x80;
    lastBlock = xorBlock(padded, K2);
  } else {
    const start = (n - 1) * blockSize;
    const end = message.length;
    const M_last = message.slice(start, end);

    if (isComplete) {
      lastBlock = xorBlock(M_last, K1);
    } else {
      const padded = new Uint8Array(blockSize);
      padded.set(M_last, 0);
      padded[M_last.length] = 0x80;
      lastBlock = xorBlock(padded, K2);
    }
  }

  let X = new Uint8Array(blockSize); // X_0 = 0^128
  const ivZero = new Uint8Array(blockSize);

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

  const Y_last = xorBlock(X, lastBlock);
  const encLast = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-CBC", iv: ivZero },
      cryptoKey,
      Y_last,
    ) as ArrayBuffer,
  );

  return encLast.slice(0, blockSize); // full 16-byte CMAC
}

// Truncate CMAC to 8 bytes (16 hex chars):
// take S1, S3, S5, S7, S9, S11, S13, S15 (odd indices, in order).
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

// Build SV2 for Session MAC key:
// SV2 = 3CC3 0001 0080 [UID (7B MSB)] [SDMReadCtr (3B LSB)]
// cntHex is a 6-hex-digit string: "000001", "00000A", etc.
function buildSV2(uid: Uint8Array, cntHex: string): Uint8Array {
  if (uid.length !== 7) {
    throw new Error("UID must be 7 bytes");
  }

  const ctrInt = parseInt(cntHex, 16);
  if (!Number.isFinite(ctrInt) || ctrInt < 0 || ctrInt > 0xFFFFFF) {
    throw new Error("Counter out of range (hex 000000..FFFFFF)");
  }

  const ctr = new Uint8Array(3);
  // LSB first for SDMReadCtr
  ctr[0] = ctrInt & 0xff;
  ctr[1] = (ctrInt >> 8) & 0xff;
  ctr[2] = (ctrInt >> 16) & 0xff;

  const sv2 = new Uint8Array(16);
  sv2.set([0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80], 0); // 6 bytes
  sv2.set(uid, 6);          // UID (7 bytes) → positions 6..12
  sv2.set(ctr, 13);         // Counter (3 bytes) → positions 13..15

  return sv2;
}

// Compute expected SUN / SDMMAC for given id & cnt
// idHex: 14 hex chars (7-byte UID MSB)
// cntHex: 6 hex chars (e.g. "000001", "00000A")
async function computeExpectedSig(idHex: string, cntHex: string): Promise<string> {
  if (!/^[0-9A-Fa-f]{14}$/.test(idHex)) {
    throw new Error("id must be 14 hex characters (7-byte UID).");
  }
  if (!/^[0-9A-Fa-f]{6}$/.test(cntHex)) {
    throw new Error("cnt must be 6 hex characters (e.g. 000001, 00000A).");
  }

  const uid = hexToBytes(idHex);
  const sv2 = buildSV2(uid, cntHex);
  const K_SDM = hexToBytes(K_SDM_HEX);

  const kSesMac = await aesCmac(K_SDM, sv2);
  const cmacFull = await aesCmac(kSesMac, new Uint8Array([]));
  return truncateMac(cmacFull);
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
    const msg = `Missing parameters. Expected: ?id=<14hex>&cnt=<000001hex>&sig=<16hex> (version: ${API_VERSION})`;
    if (MODE === "redirect") {
      // For missing params, treat as invalid and redirect to INVALID page
      return Response.redirect(INVALID_REDIRECT_URL, 302);
    }
    return new Response(msg, { status: 400 });
  }

  try {
    const expected = await computeExpectedSig(id, cnt);
    const valid = expected === sig;

    if (MODE === "redirect") {
      // Redirect mode: send user to valid / invalid landing page
      const target = valid ? VALID_REDIRECT_URL : INVALID_REDIRECT_URL;
      return Response.redirect(target, 302);
    }

    // JSON mode: return detailed validation result
    const body = {
      version: API_VERSION,
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
    if (MODE === "redirect") {
      // On errors, also go to invalid page
      return Response.redirect(INVALID_REDIRECT_URL, 302);
    }
    return new Response(
      `Error (${API_VERSION}): ${(err as Error).message}`,
      { status: 400 },
    );
  }
});

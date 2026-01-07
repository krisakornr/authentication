import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

// MODE: "json" → return JSON validation result
//       "redirect" → HTTP redirect to valid/invalid URLs per product
const MODE: "json" | "redirect" = "redirect"; // change to "redirect" for demo

// Enable / disable replay protection
const REPLAY_PROTECTION = true;

const API_VERSION = "sun-424-v9";

// SDMFileReadKey (Key0) – 16 bytes, AD repeated 16 times
const K_SDM_HEX = "AD".repeat(16);

// Per-product redirect routes (used only when MODE === "redirect")
// You can customize per product easily here.
const PRODUCT_ROUTES: Record<string, { valid: string; invalid: string }> = {
  "0001": {
    valid: "https://d.atma.to/pharmademo/PCJW8NWE63",
    //valid: "https://mm.group/",
    //invalid: "https://d.atma.to/pharmademo/GVDM4H9JE8",
    invalid: "https://d.atma.to/pharmademo/BNCV8A4QZX",
  },
  "0002": {
    valid: "https://d.atma.to/pharmademo/GVDM4H9JE8", // change if you want separate URLs
    //valid: "https://mm.group/packaging/products/shaped-cartons/", // change if you want separate URLs
    invalid: "https://d.atma.to/pharmademo/QNCM49HTNV",
  },
};

// Fallback redirect if prod not recognized
const DEFAULT_ROUTES = {
  valid: "https://d.atma.to/pharmademo/PCJW8NWE63",
  invalid: "https://d.atma.to/pharmademo/GVDM4H9JE8",
};

// -----------------------------------------------------------------------------
// Deno KV for replay protection
// -----------------------------------------------------------------------------

// Key format in KV: ["sun424", "prod", prod, "uid", id] → lastCounter (number)
const kv = await Deno.openKv();

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

// Replay protection: ensure counter is strictly increasing per (prod, id)
async function checkAndUpdateCounter(
  prod: string,
  id: string,
  cntHex: string,
): Promise<{ ok: boolean; reason?: string; last?: number; current?: number }> {
  if (!REPLAY_PROTECTION) {
    return { ok: true };
  }

  const key = ["sun424", "prod", prod, "uid", id];
  const entry = await kv.get<number>(key);
  const current = parseInt(cntHex, 16);

  if (entry.value === null || entry.value === undefined) {
    // First time we see this tag for this product
    await kv.set(key, current);
    return { ok: true, current };
  }

  const last = entry.value;

  if (current <= last) {
    // Replay (equal) or rollback (lower)
    return { ok: false, reason: "replay_or_rollback", last, current };
  }

  // Monotonic increase – accept and update
  await kv.set(key, current);
  return { ok: true, last, current };
}

// Resolve product routes
function getRoutesForProd(prod: string | null): { valid: string; invalid: string } {
  if (!prod) return DEFAULT_ROUTES;
  return PRODUCT_ROUTES[prod] ?? DEFAULT_ROUTES;
}

// -----------------------------------------------------------------------------
// HTTP handler
// -----------------------------------------------------------------------------

serve(async (req) => {
  const url = new URL(req.url);
  const prod = url.searchParams.get("prod"); // may be null
  const id = url.searchParams.get("id") ?? "";
  const cnt = url.searchParams.get("cnt") ?? "";
  const sig = (url.searchParams.get("sig") ?? "").toUpperCase();

  const routes = getRoutesForProd(prod);

  if (!id || !cnt || !sig) {
    const msg =
      `Missing parameters. Expected: ?prod=<0001>&id=<14hex>&cnt=<000001hex>&sig=<16hex> (version: ${API_VERSION})`;
    if (MODE === "redirect") {
      return Response.redirect(routes.invalid, 302);
    }
    return new Response(msg, { status: 400 });
  }

  try {
    const expected = await computeExpectedSig(id, cnt);
    const sigValid = expected === sig;

    let replayOk = true;
    let replayInfo: { reason?: string; last?: number; current?: number } = {};

    if (sigValid) {
      replayInfo = await checkAndUpdateCounter(prod ?? "default", id, cnt);
      replayOk = replayInfo.ok;
    }

    const valid = sigValid && replayOk;

    if (MODE === "redirect") {
      const target = valid ? routes.valid : routes.invalid;
      return Response.redirect(target, 302);
    }

    // JSON mode
    const body: Record<string, unknown> = {
      version: API_VERSION,
      mode: MODE,
      replay_protection: REPLAY_PROTECTION,
      valid,
      sigValid,
      prod: prod ?? "default",
      id,
      cnt,
      expected,
      received: sig,
    };

    if (REPLAY_PROTECTION && sigValid) {
      body.replay_ok = replayOk;
      if (replayInfo.last !== undefined) body.last_counter = replayInfo.last;
      if (replayInfo.current !== undefined) body.current_counter = replayInfo.current;
      if (replayInfo.reason) body.replay_reason = replayInfo.reason;
    }

    const jsonPretty = JSON.stringify(body, null, 2);

const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>AD Authentication JSON</title>
  <style>
    body {
      background: #ffffff;
      font-family: Consolas, Monaco, monospace;
      padding: 30px;
    }
    pre {
      font-size: 32px;   /* << Increase font size here */
      line-height: 1.5;
      white-space: pre-wrap;
      word-wrap: break-word;
      color: #111;
    }
  </style>
</head>
<body>
  <pre>${jsonPretty}</pre>
</body>
</html>
`;

return new Response(html, {
  status: 200,
  headers: { "content-type": "text/html" },
});

  } catch (err) {
    if (MODE === "redirect") {
      return Response.redirect(routes.invalid, 302);
    }
    return new Response(
      `Error (${API_VERSION}): ${(err as Error).message}`,
      { status: 400 },
    );
  }
});

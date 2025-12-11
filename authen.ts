import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

// 16-byte AES-128 key as hex string: "AD" repeated 16 times (32 hex chars)
const KEY_HEX = "AD".repeat(16); // ADADAD...AD (32 chars)

// ---------- Helpers ----------

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
    .join("");
}

// Build a 16-byte block from id + cnt (simplified scheme):
// plaintext = ASCII(id + cnt) truncated or zero-padded to 16 bytes.
function buildPlaintextBlock(id: string, cnt: string): Uint8Array {
  const text = id + cnt; // e.g. "0400AABBCCDD000001"
  const enc = new TextEncoder().encode(text);
  const block = new Uint8Array(16);
  block.fill(0);
  block.set(enc.slice(0, 16), 0);
  return block;
}

// Compute simplified "SUN" signature: AES-128-CBC with zero IV over block(id+cnt),
// then take first 16 hex chars of ciphertext.
async function computeSignature(id: string, cnt: string): Promise<string> {
  // Basic format validation
  if (!/^[0-9a-fA-F]{14}$/.test(id)) {
    throw new Error("id must be 14 hex characters (7-byte UID).");
  }
  if (!/^\d{6}$/.test(cnt)) {
    throw new Error("cnt must be a 6-digit decimal string (e.g. 000001).");
  }

  const block = buildPlaintextBlock(id, cnt);

  const keyBytes = hexToBytes(KEY_HEX); // 16 bytes
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-CBC" },
    false,
    ["encrypt"],
  );

  // Zero IV for deterministic output (NOT secure, demo only)
  const iv = new Uint8Array(16);

  const ciphertextBuf = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv },
    cryptoKey,
    block,
  );

  const ciphertext = new Uint8Array(ciphertextBuf);
  const fullHex = bytesToHex(ciphertext);

  // Return first 16 hex chars as sig
  return fullHex.slice(0, 16).toUpperCase();
}

// ---------- HTTP Handler ----------

serve(async (req) => {
  const url = new URL(req.url);
  const id = url.searchParams.get("id");
  const cnt = url.searchParams.get("cnt");
  const sig = url.searchParams.get("sig");

  console.log(`Incoming request: ${req.url}`);
  console.log(`id=${id}, cnt=${cnt}, sig=${sig}`);

  if (!id || !cnt || !sig) {
    return new Response(
      "Missing query parameters. Expected: ?id=<14-hex>&cnt=<000001>&sig=<16-hex>",
      { status: 400 },
    );
  }

  // Normalize signature to uppercase for comparison
  const sigNorm = sig.toUpperCase();

  // Basic format checks
  if (!/^[0-9a-fA-F]{14}$/.test(id)) {
    return new Response("Invalid id format (must be 14 hex chars).", {
      status: 400,
    });
  }
  if (!/^\d{6}$/.test(cnt)) {
    return new Response("Invalid cnt format (must be 6 digits).", {
      status: 400,
    });
  }
  if (!/^[0-9A-F]{16}$/.test(sigNorm)) {
    return new Response("Invalid sig format (must be 16 hex chars).", {
      status: 400,
    });
  }

  try {
    const expectedSig = await computeSignature(id, cnt);
    console.log(`Expected sig=${expectedSig}`);

    if (expectedSig === sigNorm) {
      // OK – signature matches
      return new Response(
        JSON.stringify({ valid: true, id, cnt, sig: sigNorm }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    } else {
      // Mismatch
      return new Response(
        JSON.stringify({
          valid: false,
          reason: "Signature mismatch",
          expected: expectedSig,
          received: sigNorm,
        }),
        { status: 400, headers: { "content-type": "application/json" } },
      );
    }
  } catch (err) {
    console.error("Error during validation:", err);
    return new Response(`Error: ${err.message}`, { status: 400 });
  }
});

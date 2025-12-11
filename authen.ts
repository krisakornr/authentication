import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

// 32-hex-char key (16 bytes) -> "AD" repeated 16 times
const KEY_HEX = "00".repeat(16); // "ADADAD...AD" (32 chars)

// --- Helpers ---

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

// Encrypt 6-char counter using AES-128-CBC with zero IV,
// return first 16 hex chars of ciphertext.
async function encryptCounter(counter: string): Promise<string> {
  // Validate counter: exactly 6 digits
  if (!/^\d{6}$/.test(counter)) {
    throw new Error("Counter must be a 6-digit numeric string, e.g. 000001");
  }

  // Prepare 16-byte block: ASCII(counter) + zero padding
  const block = new Uint8Array(16);
  const enc = new TextEncoder().encode(counter); // 6 bytes
  block.set(enc, 0); // pad rest with zeros

  // Import AES-128 key
  const keyBytes = hexToBytes(KEY_HEX); // 16 bytes
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-CBC" },
    false,
    ["encrypt"],
  );

  // Fixed IV (16 zero bytes) – deterministic encryption
  const iv = new Uint8Array(16);

  const ciphertextBuf = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv },
    cryptoKey,
    block,
  );

  const ciphertext = new Uint8Array(ciphertextBuf);
  const fullHex = bytesToHex(ciphertext);

  // Return first 16 hex chars (8 bytes)
  return fullHex.slice(0, 16);
}

// --- HTTP handler ---

serve(async (req) => {
  const url = new URL(req.url);
  // Query parameter name: "c" (you can change this)
  const counter = url.searchParams.get("c");

  if (!counter) {
    return new Response(
      "Missing query parameter 'c' (6-digit counter, e.g. ?c=000001)",
      { status: 400 },
    );
  }

  try {
    const token = await encryptCounter(counter);
    // Plain-text response containing the 16-char token
    return new Response(token, {
      status: 200,
      headers: { "content-type": "text/plain" },
    });
  } catch (err) {
    console.error("Encryption error:", err);
    return new Response(`Error: ${err.message}`, { status: 400 });
  }
});

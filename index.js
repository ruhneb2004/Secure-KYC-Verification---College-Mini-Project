const crypto = require("crypto");
const fs = require("fs");
const readline = require("readline");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});
const ask = (q) => new Promise((r) => rl.question(q, r));

// Generate RSA keypair for one authority
function generateKeyPair(i) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  fs.writeFileSync(`public_${i}.pem`, publicKey);
  fs.writeFileSync(`private_${i}.pem`, privateKey);
  console.log(`  Generated public_${i}.pem & private_${i}.pem`);
}

// One encryption layer: AES encrypts data, RSA wraps the AES key
// Stored as: [4B keyLen][RSA-wrapped AES key][16B iv][ciphertext]
function encryptLayer(data, pubPem) {
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
  const ct = Buffer.concat([c.update(data), c.final()]);
  const wk = crypto.publicEncrypt(
    {
      key: pubPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    aesKey,
  );
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(wk.length);
  return Buffer.concat([lenBuf, wk, iv, ct]);
}

// One decryption layer: unwrap AES key with RSA, decrypt data
function decryptLayer(data, privPem) {
  let off = 0;
  const wkLen = data.readUInt32BE(off);
  off += 4;
  const wk = data.slice(off, off + wkLen);
  off += wkLen;
  const iv = data.slice(off, off + 16);
  off += 16;
  const ct = data.slice(off);
  const aesKey = crypto.privateDecrypt(
    {
      key: privPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    wk,
  );
  const d = crypto.createDecipheriv("aes-256-cbc", aesKey, iv);
  return Buffer.concat([d.update(ct), d.final()]);
}

// Encrypt: authority 1 → 2 → ... → N
function sequentialEncrypt(text, n) {
  let data = Buffer.from(text, "utf8");
  for (let i = 1; i <= n; i++)
    data = encryptLayer(data, fs.readFileSync(`public_${i}.pem`, "utf8"));
  return data;
}

// Decrypt: authority N → ... → 2 → 1  (must be in reverse order)
function sequentialDecrypt(data, n) {
  for (let i = n; i >= 1; i--)
    data = decryptLayer(data, fs.readFileSync(`private_${i}.pem`, "utf8"));
  return data;
}

async function main() {
  console.log("\n1. Encrypt\n2. Decrypt");
  const mode = await ask("Choice: ");

  if (mode === "1") {
    const n = parseInt(await ask("Number of authorities: "));
    const text = await ask("Text to encrypt: ");
    for (let i = 1; i <= n; i++) generateKeyPair(i);
    fs.writeFileSync(
      "encrypted.txt",
      sequentialEncrypt(text, n).toString("base64"),
    );
    fs.writeFileSync("config.json", JSON.stringify({ n }));
    console.log("\nDone. encrypted.txt saved.");
  } else if (mode === "2") {
    const { n } = JSON.parse(fs.readFileSync("config.json"));
    const data = Buffer.from(
      fs.readFileSync("encrypted.txt", "utf8"),
      "base64",
    );
    const result = sequentialDecrypt(data, n).toString("utf8");
    fs.writeFileSync("decrypted.txt", result);
    console.log("\nResult:", result);
  }

  rl.close();
}

main();

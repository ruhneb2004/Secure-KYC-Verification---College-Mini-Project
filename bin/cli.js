#!/usr/bin/env node
"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");
const readline = require("node:readline/promises");
const { stdin, stdout } = require("node:process");

const kyc = require("../index");

async function main() {
  const rl = readline.createInterface({ input: stdin, output: stdout });

  try {
    stdout.write(
      [
        "",
        "1. Generate authority keys (central demo)",
        "2. Generate one authority-local keypair",
        "3. Encrypt payload using authority directory",
        "4. Encrypt payload using collected public keys",
        "5. Decrypt payload using authority directory",
        "6. Decrypt one authority layer locally",
        "7. Backup authority private key into shares",
        "8. Recover authority private key from shares",
        "",
      ].join("\n"),
    );

    const choice = (await rl.question("Choice: ")).trim();

    if (choice === "1") {
      const count = Number.parseInt(await rl.question("Authority count: "), 10);
      const authoritiesDir = (await rl.question("Authorities directory [./keys]: ")).trim() || "./keys";
      const overwrite = ((await rl.question("Overwrite existing keys? [y/N]: ")).trim() || "n")
        .toLowerCase()
        .startsWith("y");

      const result = await kyc.generateAuthorities(count, { authoritiesDir, overwrite });
      stdout.write(`\nCreated ${result.count} authorities in ${result.authoritiesDir}\n`);
      return;
    }

    if (choice === "2") {
      const outputDir =
        (await rl.question("Authority output directory [./authority]: ")).trim() || "./authority";
      const overwrite = ((await rl.question("Overwrite existing key files? [y/N]: ")).trim() || "n")
        .toLowerCase()
        .startsWith("y");

      const result = await kyc.generateAuthorityKeyPair({ outputDir, overwrite });
      stdout.write(
        [
          "",
          `Authority keypair created in ${result.outputDir}`,
          `Public key: ${result.publicKeyPath}`,
          `Private key: ${result.privateKeyPath}`,
          "",
        ].join("\n"),
      );
      return;
    }

    if (choice === "3") {
      const authoritiesDir = (await rl.question("Authorities directory [./keys]: ")).trim() || "./keys";
      const countInput = (await rl.question("Authority count [auto]: ")).trim();
      const payloadInput = await rl.question("JSON or string payload: ");
      const outputPath =
        (await rl.question("Write ciphertext to file [./encrypted.txt]: ")).trim() || "./encrypted.txt";

      const payload = tryParseJson(payloadInput);
      const ciphertext = await kyc.encrypt(payload, {
        authoritiesDir,
        count: countInput ? Number.parseInt(countInput, 10) : undefined,
      });

      await fs.writeFile(path.resolve(process.cwd(), outputPath), ciphertext, "utf8");
      stdout.write(`\nCiphertext written to ${path.resolve(process.cwd(), outputPath)}\n`);
      return;
    }

    if (choice === "4") {
      const publicKeyPathsInput = await rl.question(
        "Public key paths (comma-separated): ",
      );
      const payloadInput = await rl.question("JSON or string payload: ");
      const outputPath =
        (await rl.question("Write ciphertext to file [./encrypted.txt]: ")).trim() || "./encrypted.txt";

      const publicKeys = await Promise.all(
        parseCommaSeparatedPaths(publicKeyPathsInput).map((filePath) =>
          fs.readFile(path.resolve(process.cwd(), filePath), "utf8"),
        ),
      );
      const payload = tryParseJson(payloadInput);
      const ciphertext = await kyc.encryptWithPublicKeys(payload, publicKeys);

      await fs.writeFile(path.resolve(process.cwd(), outputPath), ciphertext, "utf8");
      stdout.write(`\nCiphertext written to ${path.resolve(process.cwd(), outputPath)}\n`);
      return;
    }

    if (choice === "5") {
      const authoritiesDir = (await rl.question("Authorities directory [./keys]: ")).trim() || "./keys";
      const countInput = (await rl.question("Authority count [auto]: ")).trim();
      const source = await rl.question("Ciphertext or path to file: ");
      const outputPath =
        (await rl.question("Write plaintext to file [./decrypted.txt]: ")).trim() || "./decrypted.txt";

      const ciphertext = await readValueOrFile(source);
      const plaintext = await kyc.decrypt(ciphertext, {
        authoritiesDir,
        count: countInput ? Number.parseInt(countInput, 10) : undefined,
      });
      const rendered = Buffer.isBuffer(plaintext)
        ? plaintext.toString("base64")
        : typeof plaintext === "string"
          ? plaintext
          : JSON.stringify(plaintext, null, 2);

      await fs.writeFile(path.resolve(process.cwd(), outputPath), rendered, "utf8");
      stdout.write(`\nPlaintext written to ${path.resolve(process.cwd(), outputPath)}\n`);
      return;
    }

    if (choice === "6") {
      const source = await rl.question("Ciphertext or path to file: ");
      const privateKeyPath = await rl.question("Private key path: ");
      const isFinalLayer = ((await rl.question("Is this the final layer? [y/N]: ")).trim() || "n")
        .toLowerCase()
        .startsWith("y");
      const outputPath = isFinalLayer
        ? (await rl.question("Write plaintext to file [./decrypted.txt]: ")).trim() || "./decrypted.txt"
        : (await rl.question("Write inner ciphertext to file [./partially_decrypted.txt]: ")).trim() ||
          "./partially_decrypted.txt";

      const ciphertext = await readValueOrFile(source);
      const privateKeyPem = await fs.readFile(path.resolve(process.cwd(), privateKeyPath), "utf8");
      const result = kyc.decryptAuthorityLayer(ciphertext, privateKeyPem, {
        deserializePayload: isFinalLayer,
      });
      const rendered = Buffer.isBuffer(result)
        ? result.toString("base64")
        : typeof result === "string"
          ? result
          : JSON.stringify(result, null, 2);

      await fs.writeFile(path.resolve(process.cwd(), outputPath), rendered, "utf8");
      stdout.write(`\nOutput written to ${path.resolve(process.cwd(), outputPath)}\n`);
      return;
    }

    if (choice === "7") {
      const privateKeyPath = await rl.question("Private key path: ");
      const threshold = Number.parseInt(await rl.question("Threshold (M): "), 10);
      const shares = Number.parseInt(await rl.question("Total shares (N): "), 10);
      const outputPath =
        (await rl.question("Write shares JSON to file [./shares.json]: ")).trim() || "./shares.json";

      const result = await kyc.splitKey({ privateKeyPath, threshold, shares });
      await fs.writeFile(path.resolve(process.cwd(), outputPath), JSON.stringify(result, null, 2), "utf8");
      stdout.write(
        `\nRecovery shares written to ${path.resolve(process.cwd(), outputPath)}\n`,
      );
      return;
    }

    if (choice === "8") {
      const sharesPath = await rl.question("Shares JSON path: ");
      const thresholdInput = (await rl.question("Threshold [from shares]: ")).trim();
      const outputPath =
        (await rl.question("Write recovered private key to [./reconstructed_priv.pem]: ")).trim() ||
        "./reconstructed_priv.pem";

      const shares = JSON.parse(await fs.readFile(path.resolve(process.cwd(), sharesPath), "utf8"));
      await kyc.reconstructKey({
        shares,
        threshold: thresholdInput ? Number.parseInt(thresholdInput, 10) : undefined,
        outputPath: path.resolve(process.cwd(), outputPath),
      });
      stdout.write(`\nRecovered private key written to ${path.resolve(process.cwd(), outputPath)}\n`);
      return;
    }

    throw new Error("Unknown choice.");
  } finally {
    rl.close();
  }
}

function tryParseJson(value) {
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function parseCommaSeparatedPaths(value) {
  return value
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

async function readValueOrFile(input) {
  const trimmed = input.trim();
  const possiblePath = path.resolve(process.cwd(), trimmed);

  try {
    return (await fs.readFile(possiblePath, "utf8")).trim();
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return trimmed;
    }

    throw error;
  }
}

main().catch((error) => {
  console.error(`\nError: ${error.message}`);
  process.exitCode = 1;
});

"use strict";

const kyc = require("../index");

async function main() {
  // Paste authority public keys below.
  const authority1PublicKeyPem = ``;
  const authority2PublicKeyPem = ``;
  const authority3PublicKeyPem = ``;

  const publicKeys = [
    authority1PublicKeyPem,
    authority2PublicKeyPem,
    authority3PublicKeyPem,
  ].filter(Boolean);

  if (publicKeys.length === 0) {
    throw new Error("Add at least one authority public key before running this example.");
  }

  const payload = {
    customerId: "KYC-101",
    name: "Benhur P Benny",
    aadhaar: "XXXX-XXXX-2346",
    dob: "1998-01-01",
  };

  const ciphertext = await kyc.encryptWithPublicKeys(payload, publicKeys);

  console.log("Encrypted payload:");
  console.log(ciphertext);

  const aadhaarCiphertext = await kyc.encryptAadhaarWithPublicKeys(
    "234123412346",
    publicKeys,
  );

  console.log("\nEncrypted Aadhaar:");
  console.log(aadhaarCiphertext);

  console.log("\nAadhaar helpers:");
  console.log("Validation:", kyc.validateAadhaarFormat("234123412346"));
  console.log("Masked:", kyc.maskAadhaar("234123412346"));
  console.log(
    "Fingerprint:",
    kyc.fingerprintAadhaar("234123412346", "replace-this-with-your-hmac-secret"),
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

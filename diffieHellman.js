const assert = require("assert");
const fs = require("fs");
const { createECDH, createDiffieHellman, getCurves, diffieHellman, createPrivateKey, createPublicKey } = require("crypto");

/**
 * 
 * @param {string} hexStr 
 */
function genPrivatePem(hexStr) {
  const privateKeyHeader = Buffer.from("302e020100300506032b656e04220420", "hex");
  const privateKeyBuf = Buffer.concat([privateKeyHeader, Buffer.from(hexStr, "hex")]);
  return "-----BEGIN PRIVATE KEY-----\r\n" + privateKeyBuf.toString("base64") + "\r\n-----END PRIVATE KEY-----\r\n";
}

/**
 * 
 * @param {string} hexStr 
 */
function genPublicPem(hexStr) {
  const publickKeyHeader = Buffer.from("302a300506032b656e032100", "hex");
  const publickKeyBuf = Buffer.concat([publickKeyHeader, Buffer.from(hexStr, "hex")]);
  return "-----BEGIN PUBLIC KEY-----\r\n" + publickKeyBuf.toString("base64") + "\r\n-----END PUBLIC KEY-----\r\n"
}

/**
 * 
 * @param {string} privateKey 16进制32bytes随机数
 * @param {string} pubKey 16进制32bytes随机数
 */
function genSharKey(privateKeyHex, publicKeyhex) {
  const privateKeyPem = genPrivatePem(privateKeyHex);
  const publicKeyPem = genPublicPem(publicKeyhex);

  const privateKey = createPrivateKey(privateKeyPem);
  const publicKey = createPublicKey(publicKeyPem);
  const secret = diffieHellman({
    privateKey: privateKey,
    publicKey: publicKey,
  });
  return secret;
}

const secret = genSharKey(
  "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
  "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615"
);

console.log("🚀 ~ file: diffieHellman.js:24 ~ secret:", secret);


// const prime = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"

// const dh = createDiffieHellman(prime, "hex");
// dh.setPrivateKey("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "hex");
// dh.setPublicKey("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254", "hex");
// const shareSecret = dh.computeSecret("0x9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615", "hex", "hex");
// console.log("🚀 ~ file: diffieHellman.js:45 ~ shareSecret:", shareSecret);


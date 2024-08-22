const assert = require("assert");
const fs = require("fs");
const { createHash, hkdfSync, createECDH, createDiffieHellman, getCurves, diffieHellman, createPrivateKey, createPublicKey, randomBytes, createHmac } = require("crypto");

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
  const publicKeyHeader = Buffer.from("302a300506032b656e032100", "hex");
  const publicKeyBuf = Buffer.concat([publicKeyHeader, Buffer.from(hexStr, "hex")]);
  return "-----BEGIN PUBLIC KEY-----\r\n" + publicKeyBuf.toString("base64") + "\r\n-----END PUBLIC KEY-----\r\n"
}

/**
 * 
 * @param {string} privateKey 16进制32bytes随机数
 * @param {string} pubKey 16进制32bytes随机数
 */
function genShareKey(privateKeyHex, publicKeyHex) {
  const privateKeyPem = genPrivatePem(privateKeyHex);
  const publicKeyPem = genPublicPem(publicKeyHex);

  const privateKey = createPrivateKey(privateKeyPem);
  const publicKey = createPublicKey(publicKeyPem);
  const secret = diffieHellman({
    privateKey: privateKey,
    publicKey: publicKey,
  });
  return secret;
}

const secret = genShareKey(
  "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", // client private key
  "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615" // server public key
);

console.log("🚀 ~ file: diffieHellman.js:24 ~ secret:", secret);

const serverShareKey = genShareKey(
  "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf", // server private key
  "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254" // client public key
);

console.log("🚀 ~ file: diffieHellman.js:24 ~ serverShareKey:", serverShareKey);

// const prime = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"

// const dh = createDiffieHellman(prime, "hex");
// dh.setPrivateKey("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "hex");
// dh.setPublicKey("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254", "hex");
// const shareSecret = dh.computeSecret("0x9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615", "hex", "hex");
// console.log("🚀 ~ file: diffieHellman.js:45 ~ shareSecret:", shareSecret);


/**
 * 
 * @param {Buffer} clientHello 
 * @param {Buffer} serverHello 
 */
function getHelloHash(clientHello, serverHello) {
  return sha384(Buffer.concat([
    clientHello.subarray(5),
    serverHello.subarray(5),
  ]));
}

/**
 * 
 * @param {Buffer} data 
 */
function sha384(data) {
  const hash = createHash('sha384');
  hash.update(data);
  return hash.digest("hex");
}

/**
 * 
 * @param {Buffer} salt 
 * @param {Buffer} data 
 * @returns 
 */
function hmac384(salt, data) {
  const hmac = createHmac('sha384', salt);
  hmac.update(data);
  return hmac.digest("hex");
}

function hkdfExpandLabel(prk, label, context, length) {
  // Convert label and context to buffers
  const labelBuffer = Buffer.from(label);
  const contextBuffer = Buffer.from(context);

  // Calculate the info string for HKDF Expand
  const info = Buffer.concat([
    Buffer.from([length]), // Length of the derived key
    labelBuffer, // Label
    contextBuffer, // Context
  ]);

  // Derive the key using HKDF Expand
  const derivedKey = hkdfSync('sha384', prk, Buffer.alloc(0), info, length);

  return Buffer.from(derivedKey).toString('hex');
}

const clientHelloData = Buffer.from("16030100f8010000f40303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000813021303130100ff010000a30000001800160000136578616d706c652e756c666865696d2e6e6574000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d00020101003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254", "hex");
const serverHelloData = Buffer.from("160303007a020000760303707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff130200002e002b0002030400330024001d00209fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615", "hex");

const clientHello = getHelloHash(clientHelloData, serverHelloData);
console.log("🚀 ~ clientHello:", clientHello)

const zeroKey =  Buffer.alloc(48, 0);

const earlySecret = hmac384(Buffer.from([0x00, 0x00]), zeroKey);
console.log("🚀 ~ earlySecret:", earlySecret)
// 7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e716971f9362f2c2fe2a76bfd78dfec4ea9b5
const emptyHash = sha384(Buffer.alloc(0));
console.log("🚀 ~ emptyHash:", emptyHash)

// HKDF-Expand-Label(key: early_secret, label: "derived", ctx: empty_hash, len: 48)
const derivedSecret = hkdfExpandLabel(earlySecret, "derived", emptyHash, 48);
console.log("🚀 ~ derivedSecret:", derivedSecret);
// 50 1e fa af 52 99 21 25 44 4a 9f a6 2c 00 2c 07 57 70 8e 6b b1 4b f6 a7 c8 e3 c1 26 f4 9c 45 ad c5 c3 55 a6 0f 3b d9 4c a1 e0 d2 52 61 45 91 f8
// target 1591dac5cbbf0330a4a84de9c753330e92d01f0a88214b4464972fd668049e93e52f2b16fad922fdc0584478428f282b

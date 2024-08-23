const assert = require("assert");
const fs = require("fs");
const { webcrypto, createHash, hkdfSync, createECDH, createDiffieHellman, getCurves, diffieHellman, createPrivateKey, createPublicKey, randomBytes, createHmac } = require("crypto");

const { subtle } = webcrypto;

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

/**
 * 
 * @param {Buffer} buffer 
 * @param {Number} length 
 */
function padBuffer(buffer, length) {
  return Buffer.from(buffer.toString("hex").padStart(length, "0"), "hex");
}

function hkdfExpandLabel(prk, label, context, length) {
  // Convert label and context to buffers
  const labelBuffer = Buffer.from("tls13 " + label, "utf-8");

  const contextLength = context.length / 2;

  // Calculate the info string for HKDF Expand
  const info = Buffer.concat([
    padBuffer(Buffer.from([length]), 4),
    padBuffer(Buffer.from([label.length + 6]), 2),
    labelBuffer, // Label
    padBuffer(Buffer.from([contextLength]), 2),
    Buffer.from(context, "hex"), // Context
  ]);
  console.log("🚀 ~ file: diffieHellman.js:123 ~ hkdfExpandLabel ~ info:", info.toString("hex"));
  console.log("🚀 ~ file: diffieHellman.js:123 ~ hkdfExpandLabel ~ prk:", Buffer.from(prk, "hex"));

  // Derive the key using HKDF Expand
  const derivedKey = hkdfSync('sha384', prk, Buffer.from([0x00, 0x00]), info, length);

  return Buffer.from(derivedKey).toString('hex');
}

async function hkdfExpandLabel2(prk, label, context, length) {
  // Convert label and context to buffers
  const labelBuffer = Buffer.from("tls13 " + label, "utf-8");

  const contextLength = context.length / 2;

  // Calculate the info string for HKDF Expand
  const info = Buffer.concat([
    padBuffer(Buffer.from([length]), 4),
    padBuffer(Buffer.from([label.length + 6]), 2),
    labelBuffer, // Label
    padBuffer(Buffer.from([contextLength]), 2),
    Buffer.from(context, "hex"), // Context
  ]);
  console.log("🚀 ~ file: diffieHellman.js:123 ~ hkdfExpandLabel ~ info:", info.toString("hex"));

  // Derive the key using HKDF Expand
  // const derivedKey = hkdfSync('sha384', prk, Buffer.from([0x00, 0x00]), info, length);

  // return Buffer.from(derivedKey).toString('hex');
  const keyMaterial = await subtle.importKey(
    'raw',
    Buffer.from(prk, "hex"),
    {name: 'HDKF', },
    false,
    ['deriveKey']);
  const bits = await subtle.deriveBits({
    name: 'HKDF',
    hash: 'SHA-384',
    info,
    salt: Buffer.from([0x00, 0x00]),
  }, keyMaterial, length);
  return bits;
}

const clientHelloData = Buffer.from("16030100f8010000f40303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000813021303130100ff010000a30000001800160000136578616d706c652e756c666865696d2e6e6574000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d00020101003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254", "hex");
const serverHelloData = Buffer.from("160303007a020000760303707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff130200002e002b0002030400330024001d00209fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615", "hex");

const clientHello = getHelloHash(clientHelloData, serverHelloData);
console.log("🚀 ~ clientHello:", clientHello)

const zeroKey =  Buffer.alloc(48, 0);

const earlySecret = hmac384(Buffer.from([0x00, 0x00]), zeroKey);
console.log("🚀 ~ earlySecret:", earlySecret)
const emptyHash = sha384(Buffer.alloc(0));
console.log("🚀 ~ emptyHash:", emptyHash)

// HKDF-Expand-Label(key: early_secret, label: "derived", ctx: empty_hash, len: 48)
const derivedSecret = hkdfExpandLabel(earlySecret, "derived", emptyHash, 48);
console.log("🚀 ~ derivedSecret:", derivedSecret);
// target 
// 要生成的目标deriveSercret是 1591dac5cbbf0330a4a84de9c753330e92d01f0a88214b4464972fd668049e93e52f2b16fad922fdc0584478428f282b
// info 是00300d746c73313320646572697665643038b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b

// hkdfExpandLabel2(earlySecret, "derived", emptyHash, 48).then(res => {
//   console.log("🚀 ~ file: diffieHellman.js:194 ~ hkdfExpandLabel ~ res:", res);
// });
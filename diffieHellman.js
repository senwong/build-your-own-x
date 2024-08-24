const assert = require("assert");
const fs = require("fs");
const { webcrypto, createHash, hkdfSync, createECDH, createDiffieHellman, getCurves, diffieHellman, createPrivateKey, createPublicKey, randomBytes, createHmac, createDecipheriv } = require("crypto");

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
 * @param {buffer} salt 
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

/**
 * 
 * @param {string} prk 
 * @param {string} label 
 * @param {string} context 
 * @param {number} length 
 * @returns 
 */
function hkdfExpandLabel(prk, label, context, length) {
  const labelBuffer = Buffer.from("tls13 " + label, "utf-8");

  const contextLength = context.length / 2;

  // Calculate the info string for HKDF Expand
  const info = Buffer.concat([
    padBuffer(Buffer.from([length]), 4),
    padBuffer(Buffer.from([label.length + 6]), 2),
    labelBuffer, // Label
    padBuffer(Buffer.from([contextLength]), 2),
    Buffer.from(context, "hex"), // Context
  ]).toString("hex");
  // console.log("🚀 ~ hkdfExpandLabel ~ info:", info);
  
  const hexlength = length * 2; // Length in hex characters
  let hexoutput = '';
  let hexlast = '';
  let i = 1;

  while (hexoutput.length < hexlength) {
    const hexin = hexlast + info + ('0' + i.toString(16)).slice(-2); // Pad i with leading zero
    hexlast = createHmac('sha384', Buffer.from(prk, "hex"))
    .update(Buffer.from(hexin, 'hex'))
    .digest('hex');
    hexoutput += hexlast;
    i++;
  }

  return hexoutput.substring(0, hexlength);
}

/**
 * 
 * @param {string} key 
 * @param {string} iv 
 * @param {string} data 
 */
function decrypt(key, iv, authTag, recData, data) {
    
  const decipher = createDecipheriv('aes-256-gcm', Buffer.from(key, "hex"), Buffer.from(iv, "hex"));
  decipher.setAAD(recData, { encoding: "hex" });
  decipher.setAuthTag(authTag, "hex");
  
  let decryptedData = decipher.update(data, 'hex', 'hex');
  decryptedData += decipher.final('hex');
  return decryptedData;
}

const clientHelloData = Buffer.from("16030100f8010000f40303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000813021303130100ff010000a30000001800160000136578616d706c652e756c666865696d2e6e6574000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d00020101003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254", "hex");
const serverHelloData = Buffer.from("160303007a020000760303707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff130200002e002b0002030400330024001d00209fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615", "hex");

const clientHelloHash = getHelloHash(clientHelloData, serverHelloData);
console.log("🚀 ~ clientHello:", clientHelloHash)

const zeroKey =  Buffer.alloc(48, 0);

const earlySecret = hmac384(Buffer.from([0x00, 0x00]), zeroKey);
console.log("🚀 ~ earlySecret:", earlySecret)
const emptyHash = sha384(Buffer.alloc(0));
console.log("🚀 ~ emptyHash:", emptyHash)

// HKDF-Expand-Label(key: early_secret, label: "derived", ctx: empty_hash, len: 48)
const derivedSecret = hkdfExpandLabel(earlySecret, "derived", emptyHash, 48);
console.log("🚀 ~ derivedSecret:", derivedSecret);

const handshakeSecret=hmac384(Buffer.from(derivedSecret, "hex"), serverShareKey);
console.log("🚀 ~ handshakeSecret:", handshakeSecret);

const cSecret = hkdfExpandLabel(handshakeSecret, "c hs traffic", clientHelloHash, 48);
const sSecret = hkdfExpandLabel(handshakeSecret, "s hs traffic", clientHelloHash, 48);
console.log("🚀 ~ cSecret:", cSecret)
console.log("🚀 ~ sSecret:", sSecret)

const clientHandleShakeKey = hkdfExpandLabel(cSecret, "key", "", 32);
const serverHandShakeKey = hkdfExpandLabel(sSecret, "key", "", 32);
const clientHandShakeIV = hkdfExpandLabel(cSecret, "iv", "", 12);
const serverHandShakeIV = hkdfExpandLabel(sSecret, "iv", "", 12);

console.log("🚀 ~ clientHandleShakeKey:", clientHandleShakeKey)
console.log("🚀 ~ serverHandShakeKey:", serverHandShakeKey)
console.log("🚀 ~ clientHandShakeIV:", clientHandShakeIV)
console.log("🚀 ~ serverHandShakeIV:", serverHandShakeIV)


const authTag = "9ddef56f2468b90adfa25101ab0344ae";
const recData="1703030017";
const decryptData = decrypt(serverHandShakeKey, serverHandShakeIV, authTag, recData, "6be02f9da7c2dc");
console.log("🚀 ~ decryptData:", decryptData)

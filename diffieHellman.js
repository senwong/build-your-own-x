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

const gcm_ivlen = 12;

/**
 * 
 * @param {string} iv 
 * @param {number} seq recor index, 从0开始
 */
function buildIV(iv, seq) {
  for (let i = 0; i < 8; i++) {
    iv[gcm_ivlen - 1 - i] ^= ((seq>>(i*8))&0xFF)
  }
  return iv;
}

/**
 * 
 * @param {Buffer} key 
 * @param {Buffer} iv 
 * @param {Buffer} recData 
 * @param {Buffer} data
 * @param {Buffer} authTag 
 * @param {number} recordNum 
 */
function decrypt(key, iv, recData, data, authTag, recordNum) {
  console.log("🚀 ~ file: diffieHellman.js:173 ~ decrypt ~ iv:", iv);
  buildIV(iv, recordNum);
  console.log("🚀 ~ file: diffieHellman.js:184 ~ decrypt ~ iv:", iv);
    
  const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: authTag.length });
  decipher.setAuthTag(authTag);
  decipher.setAAD(recData);
  decipher.setAutoPadding(true);
  
  let decryptedData = decipher.update(data, "binary", 'hex');
  // decipher.final("hex");
  try {
    decryptedData += decipher.final("hex");
  } catch (error) {
    console.error('Decryption failed:', error);
  }
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

let clientHandleShakeKey = hkdfExpandLabel(cSecret, "key", "", 32);
let serverHandShakeKey = hkdfExpandLabel(sSecret, "key", "", 32);
let clientHandShakeIV = hkdfExpandLabel(cSecret, "iv", "", 12);
let serverHandShakeIV = hkdfExpandLabel(sSecret, "iv", "", 12);

clientHandleShakeKey = Buffer.from(clientHandleShakeKey, "hex");
serverHandShakeKey = Buffer.from(serverHandShakeKey, "hex");
clientHandShakeIV = Buffer.from(clientHandShakeIV, "hex");
serverHandShakeIV = Buffer.from(serverHandShakeIV, "hex");
console.log("🚀 ~ clientHandleShakeKey:", clientHandleShakeKey)
console.log("🚀 ~ serverHandShakeKey:", serverHandShakeKey)
console.log("🚀 ~ clientHandShakeIV:", clientHandShakeIV)
console.log("🚀 ~ serverHandShakeIV:", serverHandShakeIV)


// const authTag = "9ddef56f2468b90adfa25101ab0344ae";
// const recData="1703030017";
// const decryptData = decrypt(serverHandShakeKey, serverHandShakeIV, authTag, recData, "6be02f9da7c2dc");
// console.log("🚀 ~ decryptData:", decryptData)


/**
 * 
 * @param {Buffer} wrappedRecord 加密的record buffer data
 */
function decryptWrappedRecord(wrappedRecord, recordNum) {
  const recData = wrappedRecord.subarray(0, 5);
  const encryptedData = wrappedRecord.subarray(5, -16);
  const authTag = wrappedRecord.subarray(-16);
  
  console.log("begin decrypt data =================================");
  console.log("recData ", recData.toString("hex"));
  console.log("encryptedData ", encryptedData.toString("hex"));
  console.log("authTag ", authTag.toString("hex"));
  
  
  const decryptData = decrypt(Buffer.from(serverHandShakeKey), Buffer.from(serverHandShakeIV), recData, encryptedData, authTag, recordNum);
  return decryptData;
}
let recordNum = 0;
let recordData = Buffer.from("17030300176be02f9da7c2dc9ddef56f2468b90adfa25101ab0344ae", "hex");
const decryptData = decryptWrappedRecord(recordData, recordNum);
console.log("🚀 ~ file: diffieHellman.js:229 ~ decryptData:", decryptData);


recordNum = 1;
recordData = Buffer.from("1703030343baf00a9be50f3f2307e726edcbdacbe4b18616449d46c6207af6e9953ee5d2411ba65d31feaf4f78764f2d693987186cc01329c187a5e4608e8d27b318e98dd94769f7739ce6768392caca8dcc597d77ec0d1272233785f6e69d6f43effa8e7905edfdc4037eee5933e990a7972f206913a31e8d04931366d3d8bcd6a4a4d647dd4bd80b0ff863ce3554833d744cf0e0b9c07cae726dd23f9953df1f1ce3aceb3b7230871e92310cfb2b098486f43538f8e82d8404e5c6c25f66a62ebe3c5f26232640e20a769175ef83483cd81e6cb16e78dfad4c1b714b04b45f6ac8d1065ad18c13451c9055c47da300f93536ea56f531986d6492775393c4ccb095467092a0ec0b43ed7a0687cb470ce350917b0ac30c6e5c24725a78c45f9f5f29b6626867f6f79ce054273547b36df030bd24af10d632dba54fc4e890bd0586928c0206ca2e28e44e227a2d5063195935df38da8936092eef01e84cad2e49d62e470a6c7745f625ec39e4fc23329c79d1172876807c36d736ba42bb69b004ff55f93850dc33c1f98abb92858324c76ff1eb085db3c1fc50f74ec04442e622973ea70743418794c388140bb492d6294a0540e5a59cfae60ba0f14899fca71333315ea083a68e1d7c1e4cdc2f56bcd6119681a4adbc1bbf42afd806c3cbd42a076f545dee4e118d0b396754be2b042a685dd4727e89c0386a94d3cd6ecb9820e9d49afeed66c47e6fc243eabebbcb0b02453877f5ac5dbfbdf8db1052a3c994b224cd9aaaf56b026bb9efa2e01302b36401ab6494e7018d6e5b573bd38bcef023b1fc92946bbca0209ca5fa926b4970b1009103645cb1fcfe552311ff730558984370038fd2cce2a91fc74d6f3e3ea9f843eed356f6f82d35d03bc24b81b58ceb1a43ec9437e6f1e50eb6f555e321fd67c8332eb1b832aa8d795a27d479c6e27d5a61034683891903f66421d094e1b00a9a138d861e6f78a20ad3e1580054d2e305253c713a02fe1e28deee7336246f6ae34331806b46b47b833c39b9d31cd300c2a6ed831399776d07f570eaf0059a2c68a5f3ae16b617404af7b7231a4d942758fc020b3f23ee8c15e36044cfd67cd640993b16207597fbf385ea7a4d99e8d456ff83d41f7b8b4f069b028a2a63a919a70e3a10e3084158faa5bafa30186c6b2f238eb530c73e", "hex");
const decryptData2 = decryptWrappedRecord(recordData, recordNum);
console.log("🚀 ~ file: diffieHellman.js:229 ~ decryptData2:", decryptData2);


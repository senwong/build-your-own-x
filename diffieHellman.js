const {  createHash, diffieHellman, createPrivateKey, createPublicKey, createHmac, createDecipheriv } = require("crypto");
const { bufToDecimal } = require("./utils");

/**
 * 
 * @param {Buffer} hexStr 
 */
function genPrivatePem(hexStr) {
  const privateKeyHeader = Buffer.from("302e020100300506032b656e04220420", "hex");
  const privateKeyBuf = Buffer.concat([privateKeyHeader, Buffer.from(hexStr, "hex")]);
  return "-----BEGIN PRIVATE KEY-----\r\n" + privateKeyBuf.toString("base64") + "\r\n-----END PRIVATE KEY-----\r\n";
}

/**
 * 
 * @param {Buffer} hexStr 
 */
function genPublicPem(hexStr) {
  const publicKeyHeader = Buffer.from("302a300506032b656e032100", "hex");
  const publicKeyBuf = Buffer.concat([publicKeyHeader, Buffer.from(hexStr, "hex")]);
  return "-----BEGIN PUBLIC KEY-----\r\n" + publicKeyBuf.toString("base64") + "\r\n-----END PUBLIC KEY-----\r\n"
}

/**
 * 
 * @param {Buffer} privateKey 16进制32bytes随机数
 * @param {Buffer} pubKey 16进制32bytes随机数
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
 * @param {Buffer} clientHello 
 * @param {Buffer} serverHello 
 * @param {Buffer} serverExtensions 
 * @param {Buffer} serverCert 
 * @param {Buffer} serverCertVerify 
 * @param {Buffer} serverFinished 
 */
function getHandShakeHash(clientHello, serverHello, decryptedData) {
 console.log("🚀 ~ getHandShakeHash ~ serverHello:", serverHello)
 console.log("🚀 ~ getHandShakeHash ~ clientHello:", clientHello)
 
  const splittedData = splitDecryptData(decryptedData.subarray(0, -1));
  
  const serverExtensions = getServerExtensions(splittedData);
  const serverCert = getServerCert(splittedData);
  const serverCertVerify = getServerCertVerify(splittedData);
  console.log("🚀 ~ getHandShakeHash ~ serverCertVerify:", serverCertVerify.toString("hex"));
  const serverFinished = getServerFinished(splittedData);
  
  return sha384(Buffer.concat([
    clientHello.subarray(5),
    serverHello.subarray(5),
    serverExtensions,
    serverCert,
    serverCertVerify,
    serverFinished
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
  const nonce = Buffer.from(iv);  // Create a copy of the original IV
  for (let i = 0; i < 8; i++) {
    nonce[gcm_ivlen - 1 - i] ^= ((seq >> (i * 8)) & 0xFF);
  }
  return nonce;
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

  const nonce = buildIV(iv, recordNum);
  console.log("🚀 ~ file: diffieHellman.js:184 ~ decrypt ~ nonce:", nonce.toString("hex"));
    
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(authTag);
  decipher.setAAD(recData);
  
  let decryptedData = decipher.update(data);
  try {
    decryptedData = Buffer.concat([decryptedData, decipher.final()]);
  } catch (error) {
    console.error('Decryption failed:', error);
  }
  return decryptedData;
}


/**
 * 
 * @param {Buffer} wrappedRecord 加密的record buffer data
 */
function decryptWrappedRecord(wrappedRecord, sequenceNumber, { serverKey, serverIV }) {
  const recData = wrappedRecord.subarray(0, 5);
  const encryptedData = wrappedRecord.subarray(5, -16);
  const authTag = wrappedRecord.subarray(-16);
  
  console.log("begin decrypt data =================================");
  console.log("recData ", recData.toString("hex"));
  console.log("encryptedData ", encryptedData.toString("hex"));
  console.log("authTag ", authTag.toString("hex"));
  console.log("serverKey ", serverKey);
  console.log("serverIV ", serverIV);
  
  const decryptData = decrypt(serverKey, serverIV, recData, encryptedData, authTag, sequenceNumber);
  return decryptData;
}


function getServerHandShakeKeys(clientHelloData, serverHelloData, privateKey, publicKey) {
   
  const clientHelloHash = getHelloHash(clientHelloData, serverHelloData);

  const zeroKey =  Buffer.alloc(48, 0);

  const earlySecret = hmac384(Buffer.from([0x00, 0x00]), zeroKey);
  console.log("🚀 ~ earlySecret:", earlySecret)
  const emptyHash = sha384(Buffer.alloc(0));
  console.log("🚀 ~ emptyHash:", emptyHash)

  // HKDF-Expand-Label(key: early_secret, label: "derived", ctx: empty_hash, len: 48)
  const derivedSecret = hkdfExpandLabel(earlySecret, "derived", emptyHash, 48);
  console.log("🚀 ~ derivedSecret:", derivedSecret);
  
  const serverShareKey = genShareKey(
    privateKey, // server private key
    publicKey // client public key
  );

  const handShakeSecret = hmac384(Buffer.from(derivedSecret, "hex"), serverShareKey);
  console.log("🚀 ~ handShakeSecret:", handShakeSecret);

  const cSecret = hkdfExpandLabel(handShakeSecret, "c hs traffic", clientHelloHash, 48);
  const sSecret = hkdfExpandLabel(handShakeSecret, "s hs traffic", clientHelloHash, 48);

  const clientHandleShakeKey = hkdfExpandLabel(cSecret, "key", "", 32);
  const serverHandShakeKey = hkdfExpandLabel(sSecret, "key", "", 32);
  const clientHandShakeIV = hkdfExpandLabel(cSecret, "iv", "", 12);
  const serverHandShakeIV = hkdfExpandLabel(sSecret, "iv", "", 12);

  return {
    clientSecret: cSecret,
    handShakeSecret: Buffer.from(handShakeSecret, "hex"),
    clientKey: Buffer.from(clientHandleShakeKey, "hex"),
    serverKey: Buffer.from(serverHandShakeKey, "hex"),
    clientIV: Buffer.from(clientHandShakeIV, "hex"),
    serverIV: Buffer.from(serverHandShakeIV, "hex"),
  }
}

/**
 * 
 * @param {string} handshakeSecret 
 * @param {string} handShakeHash 
 * @returns 
 */
function getApplicationKeys(handShakeSecret, handShakeHash) {
  const emptyHash = sha384(Buffer.alloc(0));
  const zeroKey =  Buffer.alloc(48, 0);
  const derivedSecret = hkdfExpandLabel(handShakeSecret, "derived", emptyHash, 48);
  const masterSecret = hmac384(Buffer.from(derivedSecret, "hex"), zeroKey);
  
  const clientSecret =  hkdfExpandLabel(masterSecret, "c ap traffic", handShakeHash, 48);
  const serverSecret =  hkdfExpandLabel(masterSecret, "s ap traffic", handShakeHash, 48);
  
  const clientKey = hkdfExpandLabel(clientSecret, "key", "", 32);
  const serverKey = hkdfExpandLabel(serverSecret, "key", "", 32);
  const clientIV = hkdfExpandLabel(clientSecret, "iv", "", 12);
  const serverIV = hkdfExpandLabel(serverSecret, "iv", "", 12);
  return {
    clientKey: Buffer.from(clientKey, "hex"),
    serverKey: Buffer.from(serverKey, "hex"),
    clientIV: Buffer.from(clientIV, "hex"),
    serverIV: Buffer.from(serverIV, "hex"),
  };
}

/**
 * 
 * @param {Buffer} data 
 */
function splitDecryptData(data) {
  const list = [];
  let index = 0;
  while(index < data.length) {
    const type = data.subarray(index, index + 1);
    const dataLength = bufToDecimal(data.subarray(index + 1, index + 4));
    const buf = data.subarray(index, index + 4 + dataLength);
    list.push({
      type: type.toString("hex"),
      dataLength: dataLength,
      data: buf,
    });
    index += (4 + dataLength);
  }
  return list;
}

function getServerExtensions(splittedData) {
  return splittedData.find(i => i.type === "08").data;
}

function getServerCert(splittedData) {
  return splittedData.find(i => i.type === "0b").data;
}

function getServerCertVerify(splittedData) {
  return splittedData.find(i => i.type === "0f").data;
}

function getServerFinished(splittedData) {
  return splittedData.find(i => i.type === "14").data;
}

module.exports.getServerHandShakeKeys = getServerHandShakeKeys;

module.exports.decryptWrappedRecord = decryptWrappedRecord;

module.exports.splitDecryptData = splitDecryptData;

module.exports.getApplicationKeys = getApplicationKeys;

module.exports.getHandShakeHash = getHandShakeHash;


//--------------------test-----------------


function test() {
  const handshake_hash = "fa6800169a6baac19159524fa7b9721b41be3c9db6f3f93fa5ff7e3db3ece204d2b456c51046e40ec5312c55a86126f5";
  const handshake_secret = "bdbbe8757494bef20de932598294ea65b5e6bf6dc5c02a960a2de2eaa9b07c929078d2caa0936231c38d1725f179d299";
  const applicationKeys = getApplicationKeys(handshake_secret, handshake_hash);
  console.log("🚀 ~ test ~ applicationKeys:", applicationKeys)
}

// recordNum = 1;
// recordData = Buffer.from("1703030343baf00a9be50f3f2307e726edcbdacbe4b18616449d46c6207af6e9953ee5d2411ba65d31feaf4f78764f2d693987186cc01329c187a5e4608e8d27b318e98dd94769f7739ce6768392caca8dcc597d77ec0d1272233785f6e69d6f43effa8e7905edfdc4037eee5933e990a7972f206913a31e8d04931366d3d8bcd6a4a4d647dd4bd80b0ff863ce3554833d744cf0e0b9c07cae726dd23f9953df1f1ce3aceb3b7230871e92310cfb2b098486f43538f8e82d8404e5c6c25f66a62ebe3c5f26232640e20a769175ef83483cd81e6cb16e78dfad4c1b714b04b45f6ac8d1065ad18c13451c9055c47da300f93536ea56f531986d6492775393c4ccb095467092a0ec0b43ed7a0687cb470ce350917b0ac30c6e5c24725a78c45f9f5f29b6626867f6f79ce054273547b36df030bd24af10d632dba54fc4e890bd0586928c0206ca2e28e44e227a2d5063195935df38da8936092eef01e84cad2e49d62e470a6c7745f625ec39e4fc23329c79d1172876807c36d736ba42bb69b004ff55f93850dc33c1f98abb92858324c76ff1eb085db3c1fc50f74ec04442e622973ea70743418794c388140bb492d6294a0540e5a59cfae60ba0f14899fca71333315ea083a68e1d7c1e4cdc2f56bcd6119681a4adbc1bbf42afd806c3cbd42a076f545dee4e118d0b396754be2b042a685dd4727e89c0386a94d3cd6ecb9820e9d49afeed66c47e6fc243eabebbcb0b02453877f5ac5dbfbdf8db1052a3c994b224cd9aaaf56b026bb9efa2e01302b36401ab6494e7018d6e5b573bd38bcef023b1fc92946bbca0209ca5fa926b4970b1009103645cb1fcfe552311ff730558984370038fd2cce2a91fc74d6f3e3ea9f843eed356f6f82d35d03bc24b81b58ceb1a43ec9437e6f1e50eb6f555e321fd67c8332eb1b832aa8d795a27d479c6e27d5a61034683891903f66421d094e1b00a9a138d861e6f78a20ad3e1580054d2e305253c713a02fe1e28deee7336246f6ae34331806b46b47b833c39b9d31cd300c2a6ed831399776d07f570eaf0059a2c68a5f3ae16b617404af7b7231a4d942758fc020b3f23ee8c15e36044cfd67cd640993b16207597fbf385ea7a4d99e8d456ff83d41f7b8b4f069b028a2a63a919a70e3a10e3084158faa5bafa30186c6b2f238eb530c73e", "hex");
// const decryptData2 = decryptWrappedRecord(recordData, recordNum);
// console.log("🚀 ~ file: diffieHellman.js:229 ~ decryptData2:", decryptData2);


// test();

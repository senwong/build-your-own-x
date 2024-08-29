const fs = require("fs");
const net = require("net");
const { getServerHandShakeData, decryptWrappedRecord } = require("./diffieHellman");

const clientPublicKey = Buffer.from("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254", "hex");
const clientPrivateKey = Buffer.from("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "hex");

const clientHello = Buffer.from([
  0x16,0x03,0x01,0x00,0xe1,
  
  0x01,0x00,0x00,0xdd,
  // Client Version
  0x03,0x03,
  // Client Random
  0x37,0x49,0x16,0x99,0x80,0xa8,0x72,0xd1,0x57,0x3d,0x8a,0x91,0x66,0x10,0xdf,0xd3,
  0x13,0xfd,0xec,0xbe,0xd7,0xb4,0x8d,0xbd,0xbd,0x9d,0x52,0xec,0x35,0xba,0xa6,0xd8,
  // Session ID
  0x20,
  0xaa,0x2e,0x4a,0x52,0x6d,0xe0,0x78,0xbc,0xb1,0x30,0x78,0xe8,0x25,0xc1,0x22,0x04,
  0x95,0xbe,0x73,0x8f,0x27,0x0c,0xec,0xc0,0x15,0xe9,0x13,0x15,0x17,0xc5,0xae,0xee,
  // Cipher Suites
  0x00, 0x08, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0x00, 0xff,
  // Compression Methods
  0x01,0x00,
  // Extensions Length
  0x00,0x8c,
  
  // server name
  0x00,0x00,0x00,0x0f,0x00,0x0d,
  0x00,
  0x00,0x0a,
  0x67,0x6f,0x6f,0x67,0x6c,0x65,0x2e,0x63,0x6f,0x6d, // google.com
  // ext EC Point Formats
  0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,
  // ext Supported Groups
  0x00, 0x0a, 0x00, 0x16, 0x00, 0x14, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04,
  // ext Session Ticket
  0x00, 0x23, 0x00, 0x00,
  // ext Signature Algorithms
  0x00, 0x0d, 0x00, 0x1e, 0x00, 0x1c, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01,
  // ext support versions
  0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,
  // ext key share
  0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
  ...clientPublicKey,
]);
function sentClientHello(socket) {
  socket.write(clientHello, (event) => {
    console.log("🚀 ~ file: https.js:70 ~ socket.write ~ data is finally written out: event", event);
  });
}

/**
 * 把buffer data变成十进制
 * @param {Buffer} buf 
 * @returns number
 */
function bufToDecimal(buf) {
  return Number.parseInt(buf.toString("hex"), 16);
}

function isPublicKeyExt(ext) {
  return ext.type === 51;
}

function getExtensions(extensions) {
  const list = [];
  let i = 0;
  while(i < extensions.length) {
    const extLength = bufToDecimal(extensions.subarray(i + 2, i + 4));
    const ext = {
      type: bufToDecimal(extensions.subarray(i, i + 2)),
      length: extLength,
      data: extensions.subarray(i + 2 + 2, i + 2 + 2 + extLength),
    }
    list.push(ext);
    i += 2 + 2 + extLength;
  }
  return list;
}
function getServerHelloDesc(buf) {
  return {
    recordHeader: buf.subarray(0, 5),
    handshakeHeader: buf.subarray(5, 9),
    serverVersion: buf.subarray(9, 11),
    serverRandom: buf.subarray(11, 43),
    sessionID: buf.subarray(43, 76),
    cipherSuite: buf.subarray(76, 78),
    compressionMethod: buf.subarray(78, 79),
    extensionsLength: buf.subarray(79, 81),
    extensions: getExtensions(buf.subarray(81)),
    length: bufToDecimal(buf.subarray(3, 5)) + 5,
    raw: buf,
  };
}

function getPubKeyFromHello(serverHello) {
  const found = serverHello.extensions.find(i => isPublicKeyExt(i));
  return found ? found.data.subarray(4) : null;
}

function getServerHello(responseData) {
  let offset = 0, length = 5;
  if (responseData.length >= offset + length) {
    const serverHelloLength = length + Number(responseData[3]) * 256 + Number(responseData[4]);
    const serverHelloBuffer = responseData.subarray(offset, offset + serverHelloLength);
    return getServerHelloDesc(serverHelloBuffer);
  }
  return null;
}

function getChangeCipherSec(data, offset) {
  const dataLength = bufToDecimal(data.subarray(offset + 3, offset + 5));
  return {
    data: data.subarray(offset, offset + 5 + dataLength),
    length: dataLength + 5,
  }
}
function getWrappedRecord(data, offset) {
  const dataLength = bufToDecimal(data.subarray(offset + 3, offset + 5));
  return {
    data: data.subarray(offset, offset + 5 + dataLength),
    length: dataLength + 5,
  }
}
function getServerCertificateVerify(data, offset) {
  const dataLength = bufToDecimal(data.subarray(offset + 1, offset + 4));
  return {
    data: data.subarray(offset, offset + 4 + dataLength),
    length: dataLength + 4,
  }
}

function handleWrappedRecord(serverHello, recordData) {

  const privateKey = clientPrivateKey.toString("hex");
  const publicKey = getPubKeyFromHello(serverHello);
  console.log("🚀 ~ handleWrappedRecord ~ publicKey:", publicKey)
  if (!publicKey) return;
  
  const handShakeKeys = getServerHandShakeData(clientHello, serverHello.raw, privateKey, publicKey.toString("hex"));
  console.log("🚀 ~ handShakeKeys:", handShakeKeys)

  let recordNum = 0;
  // let recordData = Buffer.from(wrappedRecord, "hex");
  const decryptData = decryptWrappedRecord(recordData, recordNum, handShakeKeys);
  return decryptData;
}

function logData(buf, name) {
  fs.writeFileSync(name, buf.toString("hex"), { encoding: "utf-8" });
}


function startHttpSocket(url, callback) {
  // http.get(url, callback);
  const socket = new net.Socket();
  // socket.setEncoding("");
  socket.connect({
    port: 443,
    host: "google.com",
    onread: {
      // Reuses a 4KiB Buffer for every read from the socket.
      buffer: Buffer.alloc(4 * 1024),
      callback: function(nread, buf) {
        // Received data is available in `buf` from 0 to `nread`.
        console.log(buf.toString('utf8', 0, nread));
      },
    },
  }); 
  socket.on("connect", () => {
    console.log("🚀 ~ file: https.js:42 ~ socket.on ~ connect:");
    // sentHeaders();
    sentClientHello(socket);
  });
  socket.on("connectionAttempt", event => {
    console.log("🚀 ~ file: https.js:47 ~ get ~ event:", event);
  });
  socket.on("connectionAttemptFailed", event => {
    console.log("🚀 ~ file: https.js:50 ~ get ~ event:", event);
  });
  socket.on("connectionAttemptTimeout", event => {
    console.log("🚀 ~ file: https.js:53 ~ get ~ event:", event);
  });
  
  let responseData = Buffer.alloc(0);
  
  socket.on('data', (data) => {
    responseData = Buffer.concat([responseData, data]);
    if (responseData.length < 6000) return;
         
    console.log("🚀 ~ file: https_google.js:198 ~ socket.on ~ responseData:", responseData.length);
    const serverHello = getServerHello(responseData);
    if (serverHello) {
      
      const changeCipherSec = getChangeCipherSec(responseData, serverHello.length);
      console.log("🚀 ~ file: https_google.js:182 ~ socket.on ~ changeCipherSec:", changeCipherSec);
      if (changeCipherSec) {
        const wrappedRecord = getWrappedRecord(responseData, serverHello.length + changeCipherSec.length)
        // handleWrappedRecord(serverHello, wrappedRecord.data);
        // console.log("🚀 ~ file: https_google.js:193 ~ socket.on ~ wrappedRecord:", wrappedRecord);
        // console.log(" total length ", serverHello.length + changeCipherSec.length + wrappedRecord.length);
        // console.log("🚀 ~ file: https_google.js:193 ~ socket.on ~ wrappedRecord:", responseData.subarray(serverHello.length + changeCipherSec.length + wrappedRecord.length));
        if (wrappedRecord) {
          // const ServerCertificateVerify = getServerCertificateVerify(responseData, serverHello.length + changeCipherSec.length + wrappedRecord.length);
          // console.log("🚀 ~ file: https_google.js:203 ~ socket.on ~ ServerCertificateVerify:", ServerCertificateVerify);
          console.log("🚀 ~ socket.on ~ wrappedRecord:", wrappedRecord)
          const decryptedData = handleWrappedRecord(serverHello, wrappedRecord.data);
          logData(serverHello.raw, "serverHello2");
          logData(changeCipherSec.data, "changeCipherSec2");
          logData(wrappedRecord.data, "wrappedRecord2")
          logData(decryptedData, "decryptedData")
        }
        
      }
    }
    
    // processData(responseData);
    
  });
  socket.on('end', (end) => {
    console.log("🚀 ~ file: https.js:104 ~ socket.on ~ end:", end);
  });
  socket.on("error", error => {
    console.log("🚀 ~ file: https.js:109 ~ get ~ error:", error);
  });
}

startHttpSocket();

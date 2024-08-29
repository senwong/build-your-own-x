const { createHmac, createHash } = require("crypto");

/**
 * 把buffer data变成十进制
 * @param {Buffer} buf 
 * @returns number
 */
function bufToDecimal(buf) {
  return Number.parseInt(buf.toString("hex"), 16);
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

function sha384(data) {
  const hash = createHash('sha384');
  hash.update(data);
  return hash.digest();
}

/**
 * 
 * @param {Buffer} buffer 
 * @param {Number} length 
 */
function padBuffer(buffer, length) {
  return Buffer.from(buffer.toString("hex").padStart(length, "0"), "hex");
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

module.exports = {
  bufToDecimal,
  hmac384,
  sha384,
  padBuffer,
  buildIV,
}

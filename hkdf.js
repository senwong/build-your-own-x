const { createHmac } = require("crypto");
const { padBuffer } = require("./utils");


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


module.exports = {
  hkdfExpandLabel,
}
const CryptoJS = require('./crypto-js');
const key = "CTQcvxlbghhVqP6rNPnF0w=="; // random key that we do not control for test purposes

const base64Charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
let plaintext = atob(process.argv[2]) || "helloworld";

const newReverseMap = [];
for (var j = 0; j < base64Charset.length; j++) {
    newReverseMap[base64Charset.charCodeAt(j)] = 0;
}

let newBase64Alphabet = base64Charset;
let normalBase64ToNewBase64 = {};
for (let i = 0; i < base64Charset.length; i++) {
    newBase64Alphabet = newBase64Alphabet.substr(0, i) + String.fromCharCode(base64Charset.charCodeAt(i) + 128) + newBase64Alphabet.substr(i + 1);
}

for (let i = 0; i < newBase64Alphabet.length; i++) {
    normalBase64ToNewBase64[base64Charset[i]] = newBase64Alphabet[i];
    newReverseMap[newBase64Alphabet.charCodeAt(i)] = i;
}

// step 2. encode and encrypt a message with null keys

const encryptNote = ({ plaintext }) => {
  const zero16bytes = 'AAAAAAAAAAAAAAAAAAAAAA==';
  const rawKey = CryptoJS.enc.Base64.parse(zero16bytes);
  const rawIv = CryptoJS.enc.Base64.parse(zero16bytes);
  const rawSalt = CryptoJS.lib.WordArray.random(16);
  const rawCiphertext = CryptoJS.AES.encrypt(plaintext, rawKey, {
    iv: rawIv, 
    salt: rawSalt, 
  }).ciphertext;
  return {
    iv: rawIv.toString(CryptoJS.enc.Base64), 
    ciphertext: rawCiphertext.toString(CryptoJS.enc.Base64), 
  }
}

let ciphertext = "";
while (true) {
    const encrypted = encryptNote({ "plaintext": plaintext });
    let ciphertextRes = encrypted.ciphertext;
    if (ciphertextRes.indexOf("=") === -1) {
        ciphertext = ciphertextRes;
        break // does not have padding, good
    } else {
        plaintext += "a"; // add a character to the plaintext
    }
}

let newCiphertext = "";
for (let i = 0; i < ciphertext.length; i++) {
  newCiphertext += normalBase64ToNewBase64[ciphertext[i]];
}
let newReverseMapDict = {};
for (let i = 0; i < newReverseMap.length; i++) {
    if (newReverseMap[i] !== undefined) {
        newReverseMapDict[i] = newReverseMap[i];
    }
}
console.log(JSON.stringify(newReverseMapDict));
console.log()
console.log("AAAAAAAAAAAAAAAAAAAAAA==");
console.log()
console.log(btoa(newCiphertext));
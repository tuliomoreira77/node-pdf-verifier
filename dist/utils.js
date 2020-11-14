"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getPublicKeyPem = exports.signData = exports.verifyData = exports.decryptSignature = exports.encryptData = exports.createHashHex = exports.createHash = exports.verifyCmsSignatureWithSignedAtt = void 0;
const rsa = require("node-rsa");
const crypto = require("crypto");
const ans1 = require("./ans1");
function verifyCmsSignatureWithSignedAtt(signedAtt, signature, publicKey, messageDigest) {
    let formatedSignedAtt = createHash(Buffer.concat([ans1.forgeAns1Header(0x31, signedAtt.length), signedAtt]));
    let decryptedSig = decryptSignature(signature, publicKey);
    let hash = ans1.decodeDigestInfo(decryptedSig).digest;
    if (formatedSignedAtt.toString('hex') == hash.toString('hex')) {
        let digest = ans1.extractMessageDigest(signedAtt);
        if (digest === messageDigest) {
            return true;
        }
        else {
            return false;
        }
    }
    else {
        return false;
    }
}
exports.verifyCmsSignatureWithSignedAtt = verifyCmsSignatureWithSignedAtt;
function createHash(data) {
    const hash = crypto.createHash('sha256');
    hash.write(data);
    return hash.digest();
}
exports.createHash = createHash;
function createHashHex(data) {
    const hash = crypto.createHash('sha256');
    hash.write(data);
    return hash.digest('hex');
}
exports.createHashHex = createHashHex;
function encryptData(data, privateKey) {
    const encrypt = crypto.publicEncrypt(privateKey, data);
    return encrypt;
}
exports.encryptData = encryptData;
function decryptSignature(signature, publicKey) {
    const decrypt = crypto.publicDecrypt(publicKey, signature);
    return decrypt;
}
exports.decryptSignature = decryptSignature;
function verifyData(data, signature, publicKey) {
    const verify = crypto.createVerify('SHA256');
    verify.write(data);
    return verify.verify(publicKey, signature);
}
exports.verifyData = verifyData;
function signData(data, privateKey) {
    const sign = crypto.createSign('SHA256');
    sign.write(data);
    return (sign.sign(privateKey, 'base64'));
}
exports.signData = signData;
function getPublicKeyPem(rawPublicKey) {
    var publicKey = new rsa();
    publicKey.importKey({
        n: Buffer.from(rawPublicKey.modulus, 'hex'),
        e: rawPublicKey.expoent,
    }, 'components-public');
    var pemKey = publicKey.exportKey('pkcs8-public-pem');
    return pemKey;
}
exports.getPublicKeyPem = getPublicKeyPem;
//# sourceMappingURL=utils.js.map
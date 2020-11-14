import * as rsa from 'node-rsa';
import * as crypto from 'crypto';
import * as ans1 from './ans1';


export function verifyCmsSignatureWithSignedAtt(signedAtt:any, signature:any, publicKey:any, messageDigest:any) {
    let formatedSignedAtt = createHash(Buffer.concat([ans1.forgeAns1Header(0x31, signedAtt.length), signedAtt]));
    let decryptedSig = decryptSignature(signature, publicKey);
    let hash = ans1.decodeDigestInfo(decryptedSig).digest;

    if(formatedSignedAtt.toString('hex') == hash.toString('hex')) {
        let digest = ans1.extractMessageDigest(signedAtt);
        if(digest === messageDigest) {
            return true;
        } else {
            return false;
        }
    } else {
        return false;
    }
}

export function createHash(data:any):Buffer {
    const hash = crypto.createHash('sha256');
    hash.write(data);
    return hash.digest();
}

export function createHashHex(data:any):string {
    const hash = crypto.createHash('sha256');
    hash.write(data);
    return hash.digest('hex');
}

export function encryptData(data:Buffer, privateKey:string) {
    const encrypt = crypto.publicEncrypt(privateKey, data);
    return encrypt;
}
export function decryptSignature(signature:any, publicKey:string) {
    const decrypt = crypto.publicDecrypt(publicKey, signature);
    return decrypt;
}

export function verifyData(data:any, signature:any, publicKey:string) {
    const verify = crypto.createVerify('SHA256');
    verify.write(data);
    return verify.verify(publicKey, signature);
}
export function signData(data:any, privateKey:string) {
    const sign = crypto.createSign('SHA256');
    sign.write(data); 
    return (sign.sign(privateKey, 'base64'));
}

export function getPublicKeyPem(rawPublicKey:any) {
    var publicKey = new rsa();
    publicKey.importKey({
        n: Buffer.from(rawPublicKey.modulus, 'hex'),
        e: rawPublicKey.expoent,
    }, 'components-public');
    var pemKey = publicKey.exportKey('pkcs8-public-pem');
    return pemKey;
}
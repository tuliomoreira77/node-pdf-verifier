import * as Utils from './utils';
import * as parser from './asn1-parser';

/**Utilities to decodes the CMS content and certificates
 * 
 */

/**Utilidades para decodificar os conteudos de assinaturas CMS e certificados digitais codificados em ANS1
 * 
 */

const oidSignedData = Buffer.from([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]);
const oidData = Buffer.from([0x06, 0x09, 0x2A, 0x86, 0x48 , 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01]);
const oidObjectIdentifier = Buffer.from([0x06]);
const oidSequence = Buffer.from([0x30]);
const oidSet = Buffer.from([0x31]);
const oid0 = Buffer.from([0xA0]);
const oid1 = Buffer.from([0xA1]);
const oid2 = Buffer.from([0xA2]);
const oid3 = Buffer.from([0xA3]);
const oidUTC = Buffer.from([0x17]);
const oidInteger = Buffer.from([0x02]);
const oidOctetString = Buffer.from([0x04]);
const oidBitString = Buffer.from([0x03]);
const oidDocumentNumberCpf = Buffer.from([0x06, 0x05, 0x60, 0x4C, 0x01, 0x03, 0x01]);
const oidDocumentNumberCnpj = Buffer.from([0x06, 0x05, 0x60, 0x4C, 0x01, 0x03, 0x03]);
const publicKeyOid = Buffer.from([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]);
const signTimeOid = Buffer.from([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05]);
const commonNameOid = Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03]);
const printableStringOid = Buffer.from([0x13]);
const oidSha256 = Buffer.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
const oidMessageDigest = Buffer.from([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04]);
const oidSigningCertificate = Buffer.from([0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F]);

let cmsTemplate:any = {
    metadata: {oid: oidSequence},
    contentType: {
        metadata: {oid: oidObjectIdentifier},
    },
    cms: {
        metadata: {oid: oid0},
        signedData: {
            metadata: {oid: oidSequence},
            version: {
                metadata: {oid: oidInteger}
            },
            digestAlgortmins: {
                metadata: {oid: oidSet},
            },
            encapContentInfo: {
                metadata: {oid: oidSequence},
            },
            certificates: {
                metadata: {optional: true,oid: oid0, array:true},
                certificate: {
                    metadata: {oid: oidSequence},
                    tbsCertificate: {
                        metadata: {oid: oidSequence},
                        version: {
                            metadata: {oid: oid0}
                        },
                        serialNumber: {
                            metadata: {oid: oidInteger}
                        },
                        signature: {
                            metadata: {oid: oidSequence}
                        },
                        issuer: {
                            metadata: {oid: oidSequence}
                        },
                        validity: {
                            metadata: {oid: oidSequence}
                        },
                        subject: {
                            metadata: {oid: oidSequence}
                        },
                        subjectPublicKeyInfo: {
                            metadata: {oid: oidSequence}
                        },
                        issuerId: {
                            metadata: {oid: oid1, optional: true}
                        },
                        subjectId: {
                            metadata: {oid: oid2, optional: true}
                        },
                        extensions: {
                            metadata: {oid: oid3, optional: true}
                        },
                    },
                    signatureAlg: {
                        metadata: {oid: oidSequence},
                    },
                    signatureValue: {
                        metadata: {oid: oidBitString},
                    }
                }
            },
            crls: {
                metadata: {optional: true,oid: oid1},
            },
            signerInfos: {
                metadata: {oid: oidSet, array:true},
                signerInfo: {
                    metadata: {oid: oidSequence},
                    version: {
                        metadata: {oid: oidInteger},
                    },
                    sigId: {
                        metadata: {oid: oidSequence},
                    },
                    alg: {
                        metadata: {oid: oidSequence},
                    },
                    signedAttr: {
                        metadata: {oid: oid0, optional: true},
                    },
                    sigAlg: {
                        metadata: {oid: oidSequence},
                    },
                    signature: {
                        metadata: {oid: oidOctetString},
                    },
                    timestamp: {
                        metadata: {oid: oid1, optional: true},
                    }
                }
            }
        }
    }
}

export function decodeSignedData(cms:Buffer) {
    let ans1:any = {};
    parser.ans1Parser(cms, cmsTemplate, ans1);
    return ans1;
}

export function decodeDigestInfo(digestInfo:Buffer) {
    var cursor = {value: 0};
    cursor.value = digestInfo.indexOf(oidSequence);
    if(cursor.value == -1) {
        throw new Error('Cannot find DigestInfo');
    }
    let dInfo = parser.decodeAns1Length(digestInfo.slice(cursor.value));
    cursor.value = cursor.value + dInfo.infoLength;
    let digestInfoReponse = {
        digestAlgorithm: extractObject(cursor, digestInfo, oidSequence),
        digest: extractObject(cursor, digestInfo, oidOctetString),
    }
    return digestInfoReponse;
}

export function extractMessageDigest(signedAtt:Buffer) {
    var cursor = {value: 0};
    cursor.value = signedAtt.indexOf(oidMessageDigest, cursor.value) + oidMessageDigest.length;
    let set = extractObject(cursor, signedAtt, oidSet);
    cursor.value = 0;
    let messageDigest = extractObject(cursor, set, oidOctetString);

    return messageDigest.toString('hex');
}

export function getCertValidity(tbsCert:Buffer) {
    let validity = {
        notBefore: null,
        notAfter: null,
    }
    let cursor = {value: 0};
    validity.notBefore = extractObject(cursor, tbsCert, oidUTC);
    validity.notAfter = extractObject(cursor, tbsCert, oidUTC);

    let transform2Date = (dateBuffer:Buffer) => {
        let year = `20${dateBuffer.slice(0,2).toString()}`;
        let month = `${dateBuffer.slice(2,4).toString()}`;
        let day = `${dateBuffer.slice(4,6).toString()}`;
        let date = +new Date(+year, +month, +day);
        return date;
    }

    return {notBefore: transform2Date(validity.notBefore), notAfter: transform2Date(validity.notAfter)};
}

/**Busca o commonName de um certificado
 * cada certificado na cadeia possui um, o ultimo 'commonName' na cadeia corresponde ao do dono do certificado
 */
/**Finds the commoName of the certificate
 * the last commonName in chain is about the onwer of the certificate
 */
export function extractCommonName(data:Buffer) {
    var commonNames = [];
    var cursor = 0;
    var index = data.indexOf(commonNameOid, cursor);
    while(index != -1) {
        cursor = index + commonNameOid.length;
        var length = parser.decodeAns1Length(data.slice(cursor));
        var commonName = data.slice(cursor + length.infoLength, cursor + length.infoLength + length.length);
        commonNames.push(commonName.toString());
        index = data.indexOf(commonNameOid, cursor);
    }
    return commonNames[commonNames.length -1];
}

/**
 * Here is some brazilian standats specifics
 * The signer document number (CPF) is on the extensions of the certificate 
 * */

//** TODO Implementar verificacao de pessoa juridica */
export function extractSignerDocument(data:Buffer) {
    try {
        var startIndex = 0;

        //var oidFirstIndex = data.indexOf(oidDocumentNumberCnpj, startIndex);
        //if(oidFirstIndex == -1) {
        var oidFirstIndex = data.indexOf(oidDocumentNumberCpf, startIndex);
        //}
        if(oidFirstIndex == -1) {
            throw new Error('Error finding documentNumber');
        }
        var oidIndex = oidFirstIndex + oidDocumentNumberCpf.length + 4;
        var startDocumentNumber = oidIndex + 8;
        var documentNumber = data.slice(startDocumentNumber, startDocumentNumber + 11);
        return documentNumber.toString();
    } catch(error) {
        console.log(error);
        return "";
    }
}

export function extractSignerPublicKey(data:Buffer) {

    var oidIndex = data.indexOf(publicKeyOid, 0) + 13;
    var length = parser.decodeAns1Length(data.slice(oidIndex));

    var cursor = oidIndex+length.infoLength+1;
    length = parser.decodeAns1Length(data.slice(cursor));

    cursor = cursor + length.infoLength;
    length = parser.decodeAns1Length(data.slice(cursor));
    
    cursor = cursor + length.infoLength;
    var publicKey = data.slice(cursor, cursor+length.length).toString('hex');

    cursor = cursor + length.length;
    var expoentHex = data.slice(cursor+2, cursor+5);

    var expoentNumber:number = 0;
    for(var i=0; i< expoentHex.length; i++)
        expoentNumber = (expoentNumber << 8) + expoentHex[i];
    return {
        modulus: publicKey,
        expoent: expoentNumber,
    }
}

//Extrai um objeto e avanca o cursor
export function extractObject(cursor:{value:number}, cms:Buffer, objOid?:Buffer) {
    if(objOid) {
        if(cms.indexOf(objOid, cursor.value) != cursor.value) {
            throw 'O objeto não corresponde ao procurado';
        }
    }
    let objInfo = parser.decodeAns1Length(cms.slice(cursor.value));
    let obj = cms.slice(cursor.value + objInfo.infoLength, (cursor.value + objInfo.infoLength) + objInfo.length);
    cursor.value = cursor.value + objInfo.totalLength;
    return obj;
}

export function forgeDigestInfo(hash:Buffer) {
    let algObject = createAsn1Obj(oidSequence, Buffer.concat([oidSha256, Buffer.from([0x05, 0x00])]));
    let digest = createAsn1Obj(oidOctetString, hash);
    return createAsn1Obj(oidSequence, Buffer.concat([algObject, digest]));
}

export function forgeSigningCertificate(certificate:Buffer) {
    let certHash = Utils.createHash(certificate);
    let octetHash = createAsn1Obj(oidOctetString, certHash);
    let essCertId = createAsn1Obj(oidSequence, octetHash);
    let certs = createAsn1Obj(oidSequence, essCertId);
    let signingCertificate = createAsn1Obj(oidSequence, certs);
    return signingCertificate; 
}

/**Crate an ASN1 object */
/**Cria um Objeto ASN.1 */
export function createAsn1Obj(headerOid:Buffer, content:Buffer) {
    let lenght = content.length;
    if(lenght > 127) {
        const hexBuffer = Buffer.from([lenght >> 8 | lenght]);
        const hexBufferLength = hexBuffer.length | 10000000;
        return Buffer.concat([headerOid, Buffer.from([hexBufferLength]), hexBuffer, content]);
    }
    else {
        return Buffer.concat([headerOid ,Buffer.from([lenght]), content]);
    }
}

/**Create ANS1 Header */
/**Cria um Header ANS.1 generico */
export function forgeAns1Header(firstByte:number ,lenght:number) {
    if(lenght > 127) {
        const hexBuffer = Buffer.from([lenght >> 8 | lenght]);
        const hexBufferLength = hexBuffer.length | 10000000;
        return Buffer.concat([Buffer.from([firstByte, hexBufferLength]), hexBuffer]);
    }
    else {
        return Buffer.concat([Buffer.from([firstByte]),Buffer.from([lenght])]);
    }
}
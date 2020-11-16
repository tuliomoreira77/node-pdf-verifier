
 /**Library created by tuliomoreira77@gmail.com
  * Standards can be found in adobe documentation https://www.adobe.com/devnet-docs/etk_deprecated/tools/DigSig/Acrobat_DigitalSignatures_in_PDF.pdf
  * and in RFC 5652, RFC 5280
  */

/**Biblioteca de verificacao de assinaturas digitais
 * Criada por tuliomoreira77@gmail.com
 * Os padrões podem ser encontrados na documentacao da adobe https://www.adobe.com/devnet-docs/etk_deprecated/tools/DigSig/Acrobat_DigitalSignatures_in_PDF.pdf
 * e nas RFC 5652 e RFC 5280
 */

import * as asn1 from './asn1';
import * as crypto from 'crypto';
import * as utils from './Utils';

export interface pdfSignInfo {
    cms?: Buffer 
    certificateInfo: {
        issuer: any,
        validity: {
            notBefore: number,
            notAfter:number,
        },
        publicKey: any,
    }
    signerInfo: {
        name: any,
        documentNumber: string, //Here is an brazilian cretificate (ICP-Brasil) specific standart
        signingTime?: string,
    }
    signatureInfo: {
        verified: boolean,   
    }
}

export function extractSignersInfo(pdf:Buffer) {
    let signers:Array<pdfSignInfo> = [];
    let watchDogCounter = 0;
    let cmsInfo = {cms: null, signatureBytes: null, offset: 0};
    while(watchDogCounter < 50) {
        watchDogCounter++;
        cmsInfo = extractSignatureData(pdf, cmsInfo.offset);
        if(cmsInfo == null) {
            break;
        }
        
        let _ans1 = asn1.decodeSignedData(cmsInfo.cms);
        let publicKey = utils.getPublicKeyPem(asn1.extractSignerPublicKey(_ans1.cms.signedData.certificates.certificate.tbsCertificate.subjectPublicKeyInfo));
        let pdfSignInfo = {
            certificateInfo: {
                issuer: null,
                validity: asn1.getCertValidity(_ans1.cms.signedData.certificates.certificate.tbsCertificate.validity),
                publicKey: publicKey
            },
            signerInfo: {
                name: asn1.extractCommonName(_ans1.cms.signedData.certificates.certificate.tbsCertificate.subject),
                documentNumber: asn1.extractSignerDocument(_ans1.cms.signedData.certificates.certificate.tbsCertificate.extensions),
            },
            signatureInfo: {
                verified: utils.verifyCmsSignatureWithSignedAtt(
                    _ans1.cms.signedData.signerInfos.signerInfo.signedAttr, 
                    _ans1.cms.signedData.signerInfos.signerInfo.signature, 
                    publicKey, 
                    cmsInfo.signatureBytes),
            }
        }
        signers.push(pdfSignInfo);
    }
    return signers;
}

function extractSignatureData(pdfBuffer:Buffer, offset:number) {
    var cmsInfo:any;

    const byteRangePattern = '/ByteRange';

    var byteRangeStart = pdfBuffer.indexOf(byteRangePattern, offset);
    if(byteRangeStart == -1) {
        return null;
    }
    const byteRangeEnd = pdfBuffer.indexOf(']', byteRangeStart);
    const byteRangeValue = pdfBuffer.slice(byteRangeStart + byteRangePattern.length, byteRangeEnd +1);
    var signatureRanges:Array<number> = []
    byteRangeValue.toString().split(' ').map((number) => {
        number = number.replace('[', '');
        number = number.replace(']', '');
        if(!isNaN(parseInt(number))) {
            signatureRanges.push(+number);
        }
    });
    var cmsSignature = pdfBuffer.slice(signatureRanges[1]+1, signatureRanges[2]-1);
    var EofEndIndex = pdfBuffer.indexOf('%%EOF', signatureRanges[2]) + 5;
    if(EofEndIndex !== pdfBuffer.length) {
        EofEndIndex = EofEndIndex +1;
    }
    var signatureBytes = Buffer.concat([
        pdfBuffer.slice(0, signatureRanges[1]),
        pdfBuffer.slice(signatureRanges[2], EofEndIndex),
    ]);
    offset = byteRangeStart + byteRangePattern.length + 1;

    const hash = crypto.createHash('sha256');
    hash.update(signatureBytes);
    cmsInfo = {
        cms: Buffer.from(cmsSignature.slice(0, cmsSignature.indexOf('00000000')).toString(), 'hex'),
        signatureBytes: hash.digest('hex'),
        offset: offset,
    };

    return cmsInfo;
}

 /**Extrai as assinaturas de um pdf assinado */
function extractCmsFromPdf(data:Buffer):Array<Buffer> {
    var cmsArray = [];
    const byteRangePattern = '/ByteRange';

    var byteRangeStart = data.indexOf(byteRangePattern);
    if(byteRangeStart == -1) {
        throw 'O Pdf não possui assinaturas';
    }
    while(true) {
        const byteRangeEnd = data.indexOf(']', byteRangeStart);
        const byteRangeValue = data.slice(byteRangeStart + byteRangePattern.length, byteRangeEnd +1);
        var signatureRanges:Array<number> = []
        byteRangeValue.toString().split(' ').map((number) => {
            number = number.replace('[', '');
            number = number.replace(']', '');
            if(!isNaN(parseInt(number))) {
                signatureRanges.push(+number);
            }
        });
        var cmsSignature = data.slice(signatureRanges[1]+1, signatureRanges[2]-1);
        cmsArray.push(Buffer.from(cmsSignature.slice(0, cmsSignature.indexOf('00000000')).toString(), 'hex'));

        byteRangeStart = data.indexOf(byteRangePattern, byteRangeStart + byteRangePattern.length + 1);
        if(byteRangeStart == -1) {
            break;
        }
    }
    return cmsArray;
}
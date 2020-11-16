# node-pdf-verifier
A digital signature verifier for pdf documents.

How to use:
Just pass the pdf as a Buffer and call the method 'verifyPdf(pdf:Buffer)'.

The signature is valid (the content is not modified) if the field "signatureInfo.verified" will be true, false otherwise. 

**IMPORTANT: the certificate is not verified, only the informations about it are extracted and the content signture is verified using the publicKey. Maybe in future I will add the certificate chain verification**

Returned type:
```typescript
interface pdfSignInfo {
    cms?: Buffer //Original CMS content extract from inside PDF
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
        verified: boolean, //Here will be  true if the signature is valid
    }
}

```

Exemple of use.
```javascript
import * as fs from 'fs';
import * as verifier from 'node-pdf-verifier';

function verify() {
    let pdf = fs.readFileSync('pdf.pdf');
    let signersInfo = verifier.verifyPdf(pdf);
}
```

# node-pdf-verifier
A digital signature verifier for pdf documents.

How to use:
Just pass the pdf as a Buffer.
the return type will be an object like

```typescript
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

```

```javascript
import * as fs from 'fs';
import * as verifier from 'node-pdf-verifier';

function verify() {
    let pdf = fs.readFileSync('pdf.pdf');
    let signersInfo = verifier.extractSignersInfo(pdf);
}
```

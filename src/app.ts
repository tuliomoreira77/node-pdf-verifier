import {extractSignersInfo} from './verifier';


export {pdfSignInfo} from './verifier';

export function verifyPdf(pdfBuffer:Buffer) {
    return extractSignersInfo(pdfBuffer);
}
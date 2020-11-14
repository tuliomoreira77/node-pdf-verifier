"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyPdf = void 0;
const verifier_1 = require("./verifier");
function verifyPdf(pdfBuffer) {
    return verifier_1.extractSignersInfo(pdfBuffer);
}
exports.verifyPdf = verifyPdf;
//# sourceMappingURL=app.js.map
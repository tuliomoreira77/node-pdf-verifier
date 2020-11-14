export interface Ans1Object {
    oid:Buffer,
    name:string,
    child?:Ans1Object
}

export function ans1Parser(content:Buffer, ans1Template:any, ans1?:any) {
    let fields = Object.keys(ans1Template);
    
    let self = extractObject(content);
    
    for(let fieldName of fields) {
        let field = ans1Template[fieldName];
        if(fieldName == 'metadata') {
            if(fields.length == 1) {
                return self;
            }
            continue;
        }
        if(field.metadata.array) {
            let count = calculateSetObjects(self);
            for(let i=1; i < count; i++) {
                ans1Template[fields[1] + i] = {
                    ...ans1Template[fields[1]]
                }
            }
        }
        if(self.indexOf(field.metadata.oid) != 0) {
            if(field.metadata.optional) {
                continue;
            } else {
                throw 'O objeto não corresponde ao procurado';
            }  
        }
        let objInfo = decodeAns1Length(self);
        ans1[fieldName] = {};
        ans1[fieldName] = ans1Parser(self.slice(0, objInfo.totalLength), field, ans1[fieldName]);
        self = self.slice(objInfo.totalLength);
    }

    return ans1;
}

export function calculateSetObjects(content:Buffer) {
    let self = extractObject(content);
    let count = 1;
    let cursor = {value: 0};
    let objInfo = decodeAns1Length(self);
    cursor.value = objInfo.totalLength;
    while(self.slice(cursor.value).length > 0) {
        objInfo = decodeAns1Length(self.slice(cursor.value));
        cursor.value = objInfo.totalLength;
        count++;
    }
    return count;
}

export function extractObject(cms:Buffer) {
    let objInfo = decodeAns1Length(cms);
    let obj = cms.slice(objInfo.infoLength, (objInfo.infoLength) + objInfo.length);
    return obj;
}

/**Decode ans1 content
 * length is the length of raw content
 * infoLength is the length of the header
 */
export function decodeAns1Length(data:Buffer) {
    var length = 0;
    var infoLength = 0;
    if(data[1] < 0x80) {
        length = data[1];
        infoLength = 2;
    } else {
        const lengthByteSize = data[1] & 0x7F;
        length = 0;
        for(var j=0; j < lengthByteSize; j++) {
            length = (length << 8) + data[2+j]
        }
        infoLength = lengthByteSize+2;
    }
    return {
        length: length,
        infoLength: infoLength,
        totalLength: length + infoLength,
    }
}
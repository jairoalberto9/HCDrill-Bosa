/*
* HTTP Custom module
* Description: Yeah, this covers basically all HTTP Custom encryption methods and etc
* Author: PANCHO7532
* Version: 1.1
*/
const CryptoJS = require('crypto-js');
const crypto = require('crypto');
const fs = require('fs');
const xorValues = ['。', '〃', '〄', '々', '〆', '〇', '〈', '〉', '《', '》', '「', '」', '『', '』', '【', '】', '〒', '〓', '〔', '〕'];
function xorDeobfs(file) {
    //xor deobfs
    var deobfs_val = "";
    for(a = 0, b = 0; a < file.length; a++, b++) {
        if(b >= xorValues.length) {b = 0}
        deobfs_val += String.fromCharCode(file.charCodeAt(a) ^ xorValues[b].charCodeAt(0));
    }
    return deobfs_val;
}
function sha1crypt(data) {
    var outp1 = crypto.createHash("sha1");
    outp1.update(data);
    outp1=outp1.digest('hex');
    return outp1.substring(0, outp1.length-8);
}
function aesDecrypt(data, key) {
    //aes but with raw data
    var aesoutp1 = CryptoJS.AES.decrypt(data, CryptoJS.enc.Hex.parse(key), {mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7});
    return aesoutp1.toString(CryptoJS.enc.Utf8);
}
function aesDecrypt2(data, key) {
    //aes but with base64 encoded data
    var aesoutp2 = CryptoJS.AES.decrypt(Buffer.from(data).toString("base64"), CryptoJS.enc.Hex.parse(key), {mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7});
    return aesoutp2.toString(CryptoJS.enc.Utf8);
}
function parseDecoded(data) {
    //only json, so, we parse this json inside a json later in the main bot script or any place where this is used
    var st1 = data.split("[splitConfig]");
    var outp2 = {};
    outp2["payload"] = st1[0];
    outp2["proxyURL"] = st1[1];
    outp2["blockedRoot"] = st1[2];
    outp2["lockPayloadAndServers"] = st1[3];
    outp2["expireDate"] = st1[4];
    outp2["containsNotes"] = st1[5];
    outp2["note1"] = st1[6];
    outp2["sshAddr"] = st1[7];
    outp2["mobileData"] = st1[8];
    outp2["unlockProxy"] = st1[9];
    outp2["openVPNConfig"] = st1[10];
    outp2["VPNAddr"] = st1[11];
    outp2["sslsni"] = st1[12];
    outp2["connectSSH"] = st1[13];
    outp2["udpgwPort"] = st1[14];
    outp2["lockPayload"] = st1[15];
    outp2["hwidEnabled"] = st1[16];
    outp2["hwidValue"] = st1[17];
    outp2["note2"] = st1[18];
    outp2["unlockUserAndPassword"] = st1[19];
    outp2["sslPayloadMode"] = st1[20];
    outp2["passwordProtected"] = st1[21];
    outp2["passwordValue"] = st1[22];
    outp2["raw"] = data;
    return JSON.stringify(outp2);
}
function decryptStage1(fileContent) {
    var keyFile;
    var complete = false;
    var response = {};
    response["content"] = "";
    response["error"] = 0;
    try {
        keyFile = JSON.parse(fs.readFileSync("./lib/keyFile.json").toString())["httpCustom"];
    } catch(error) {
        response["error"] = error;
        return JSON.stringify(response);
    }
    //decrypting stage
    var deXoredContent = xorDeobfs(fileContent.toString("utf-8"));
    var sha1key = "";
    for(c = 0; c < keyFile.length; c++) {
        sha1key = sha1crypt(keyFile[c]);
        try {
            response["content"] = aesDecrypt(deXoredContent, sha1key);
            if(response["content"].length > 1) {
                complete = true;
                break;
            } else {
                throw "False UTF-8";
            }
        } catch(error) {}
    }
    if(complete) {
        response["content"] = parseDecoded(response["content"]);
        return JSON.stringify(response);
    } else {
        response["error"] = 1;
        return JSON.stringify(response);
    }
}
function decryptStage2(fileContent) {
    var keyFile;
    var complete = false;
    var response = {};
    response["content"] = "";
    response["error"] = 0;
    try {
        keyFile = JSON.parse(fs.readFileSync("./lib/keyFile.json").toString())["httpCustom"];
    } catch(error) {
        response["error"] = error;
        return response;
    }
    for(c = 0; c < keyFile.length; c++) {
        try {
            response["content"] = aesDecrypt2(fileContent, sha1crypt(keyFile[c]));
            if(response["content"].length > 1) {
                complete = true;
                break;
            } else {
                throw "False UTF-8";
            }
        } catch(error) {}
    }
    if(complete) {
        response["content"] = parseDecoded(response["content"]);
        return JSON.stringify(response);
    } else {
        response["error"] = 1;
        return JSON.stringify(response);
    }
}
module.exports.decrypt = function(file) {
    //This export will be changed with a more dynamic way of importing modules in a near future.
    var pass = false;
    var validMethod = 0;
    var lastMethod = 0;
    var decMethods = [
        decryptStage1(file),
        decryptStage2(file)
    ];
    for(c = 0; c < decMethods.length; c++) {
        if(JSON.parse(decMethods[c])["error"] == 0) {
            pass = true;
            validMethod = c;
        }
        lastMethod = c;
    }
    if(pass) {
        return decMethods[validMethod];
    } else {
        return decMethods[lastMethod];
    }
}
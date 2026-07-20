const crypto = require("crypto");

let pass = crypto.randomBytes(64).toString("base64url");
console.log(pass)
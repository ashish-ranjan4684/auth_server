const crypto = require("crypto");
const fs = require("fs");
const mysql = require("mysql2");
const path = require("path");
require("dotenv").config();

let connection = mysql.createConnection({
    host:process.env.DB_HOST,
    port:process.env.DB_PORT,
    user:process.env.DB_USER,
    password:process.env.DB_PASSWORD,
    database:process.env.DATABASE,

});

(async ()=>{
    let pass = process.env.MASTER_ENCRYPTION_KEY || crypto.randomBytes(32).toString("hex");
    let kid = crypto.randomBytes(16).toString("hex");
    console.log(`PASSPHRASE: ${pass}`);
    console.log(`kid : ${kid}`);
    let {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519',{
        publicKeyEncoding:{
            type:'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
            cipher: 'aes-256-cbc',
            passphrase: pass,
        }
    });
    fs.writeFileSync(path.join(__dirname,"private_key_files","privateKey.pem"),privateKey);
    await connection.execute("INSERT INTO public_keys(kid, public_key, algorithm, created_at) VALUES (?,?,?,?)",[kid, publicKey, 'ed25519', new Date()]);
    console.log(`privatekey is : \n\n${privateKey}\n\npublic key is : \n\n${publicKey}`);
})();
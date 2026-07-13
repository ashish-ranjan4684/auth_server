const crypto = require("crypto");
const grpc = require("@grpc/grpc-js");
const protoLoader = require("@grpc/proto-loader");
const mysql = require("mysql2/promise");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

const packageDef = protoLoader.loadSync("auth.proto");
const proto = grpc.loadPackageDefinition(packageDef).auth;

let pool = mysql.createPool({
    host:process.env.DB_HOST,
    port:process.env.DB_PORT,
    user:process.env.DB_USER,
    password:process.env.DB_PASSWORD,
    database:process.env.DATABASE,

    waitForConnections:true,//queue requests when pool is full ie., connection limit is reached. eg., there are 10 simultaneous requests
    connectionLimit:10,//10%-20% of mysql's max connection
    queueLimit:0,//unlimited queue length for pending requests
    enableKeepAlive:true//prevent connection timeout ie., even if no request is sent, the connection will stay alive
});

const key = crypto.createPrivateKey({
    key: fs.readFileSync(path.join(__dirname,"private_key_files","privateKey.pem")),
    format: "pem",
    passphrase: process.env.MASTER_ENCRYPTION_KEY
});

async function rotateKey(call, callback){
    key = call.request.privateKey//

    if(!key){
        //what to do ?
    }
    else{
        return callback(null,{
            status:grpc.status.OK,
            message:"key rotated successfully."
        })
    }
}

async function login(call,callback){
    let email = call.request.email;
    let password = call.request.password;

    if(!email || !password){
        return callback(null,{
            status:grpc.status.INVALID_ARGUMENT,
            token: " "
        });
    }

    try{
        let [user] = await pool.execute(`select * from users where email=?`,[email]);
        if(user.length===0){
            console.log("user not found");
            return callback(null,{
                status: grpc.status.NOT_FOUND,
                token: " "
            });
        }
        let foundUser = user[0];
        console.log("some user found", foundUser);
        let hashedPassword = crypto.argon2Sync("argon2id",{
            message:password,
            nonce:Buffer.from(foundUser.salt,"hex"),
            parallelism:2,
            tagLength:64,
            memory:65536,
            passes:3
        }).toString("hex");
        if(hashedPassword === foundUser.password_hash){
            console.log("user found");
            console.log(hashedPassword,foundUser.password_hash)
            //send token containing name, organization and id using edDsa over hash of token
            let currTimestamp = Date.now();
            let token = {id:foundUser.id, name:foundUser.name, organization:foundUser.organization, expAt: currTimestamp+(1000*60*60*24*7), iat:currTimestamp};
            let sign = crypto.sign(null,JSON.stringify(token),key).toString("base64url");
            console.log(`${Buffer.from(JSON.stringify(token)).toString("base64url")}.${sign}`)
            callback(null,{
                token:`${Buffer.from(JSON.stringify(token)).toString("base64url")}.${sign}`,
                status:grpc.status.OK
            });

        }else{
            callback(null,{
                status:grpc.status.PERMISSION_DENIED,
                token:" "
            });
        }
    }catch(err){
        console.log(err);
        callback({
            code:grpc.status.INTERNAL,
            message: "Internal server error."
        }, null)
    }
}

async function signup(call, callback){
    let {name, email, password, organization} = call.request;

    if(!name || !email || !password){
        return callback({
            code:grpc.status.INVALID_ARGUMENT,
            message: "one or more required elements is not provided."
        }, null);
    }

    try{
        let [existingUser] = await pool.execute(`SELECT id FROM users WHERE email = ?`,[email]);
        if(existingUser.length > 0){
            return callback({
                code: grpc.status.ALREADY_EXISTS,
                message: "User already exists."
            });
        }

        const salt = crypto.randomBytes(64);
        const id = crypto.randomBytes(32).toString("hex");

        const passwordHash = crypto.argon2Sync("argon2id",{
            message: password,
            nonce:salt,
            parallelism:2,
            tagLength:64,
            memory:65536,
            passes:3
        }).toString("hex");

        await pool.execute("INSERT INTO users(id, name, email, password_hash, salt, organization) VALUES (?, ?, ?, ?, ?, ?)",[id, name, email, passwordHash, salt.toString("hex"), organization]);

        callback(null,{
            status: grpc.status.OK
        });
    }catch(err){
        callback({
            code: grpc.status.INTERNAL,
            message: `Internal Server Error. ${err}`
        }, null)
    }

}

const server = new grpc.Server();
server.addService(proto.AuthService.service,{
    Login: login,
    Signup: signup
});

const HOST = process.env.PRODUCTION==="true"?process.env.AUTH_SERVER_HOST:"0.0.0.0";
const PORT =  process.env.AUTH_SERVER_PORT || 51000;
server.bindAsync(`${HOST}:${PORT}`,
    grpc.ServerCredentials.createInsecure(),
    ()=>{
        console.log("Server is running on port: ", PORT)
    }
);
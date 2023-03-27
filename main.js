import xml2js from 'xml2js';
import crypto from 'crypto';
import axios from 'axios';
import {config} from "./config.js";

async function setupSession(server) {
    const url = `http://${server}/`;
    const cookie = await axios.get(url).then((res) => {
        return res.headers['set-cookie']
    }).catch(fail => console.error(fail))
    return cookie
}

function generateNonce() {
    return crypto.randomBytes(16).toString('hex') + crypto.randomBytes(16).toString('hex');
}

async function getServerToken(server) {
    const url = `http://${server}/api/webserver/token`;
    const data = await axios.get(url).then((res) => res.data)
        .catch((fail) => console.error(fail))
    const result = await xml2js.parseStringPromise(data);
    return result.response.token[0];
}

function getClientProof(clientNonce, serverNonce, password, salt, iterations) {
    const msg = `${clientNonce},${serverNonce},${serverNonce}`;
    const saltedPass = crypto.pbkdf2Sync(password, Buffer.from(salt, 'hex'), iterations, 32, 'sha256');
    const clientKey = crypto.createHmac('sha256', 'Client Key').update(saltedPass).digest();
    const storedKey = crypto.createHash('sha256').update(clientKey).digest();
    const signature = crypto.createHmac('sha256', storedKey).update(msg).digest();
    const clientProof = Buffer.alloc(clientKey.length);
    for (let i = 0; i < clientKey.length; i += 1) {
        clientProof[i] = clientKey[i] ^ signature[i];
    }
    return clientProof.toString('hex');
}

async function login(server, user, password) {
    const cookies = await setupSession(server)
    const token = await getServerToken(server);
    const url = `http://${server}/api/user/challenge_login`;
    const request = {
        request: {
            username: user,
            firstnonce: generateNonce(),
            mode: 1,
        },
    };
    const builder = new xml2js.Builder();
    const xml = builder.buildObject(request);
    const headers = {
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        '__RequestVerificationToken': token.substring(32),
        'Cookie': cookies[0].split('; ')[0]
    };
    console.log(headers)
    q4fW7UBdbDO0XuxFXZ8egSqe7QmyDCYO
    const response = await axios.post(url, xml, { headers })
        .then(res => {
            console.log(res.data)
        }).catch((fail) => {
            console.error(fail)
        })
    const scramData = await xml2js.parseStringPromise(response.data);
    const { servernonce: serverNonce, salt, iterations } = scramData.response;
    const verificationToken = response.headers.__RequestVerificationToken;
    const loginRequest = {
        request: {
            clientproof: getClientProof(request.request.firstnonce, serverNonce, password, salt, iterations),
            finalnonce: serverNonce,
        },
    };
    const finalHeaders = {
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        __RequestVerificationToken: verificationToken,
    };
    const result = await client.post(`http://${server}/api/user/authentication_login`, loginRequest, { headers: finalHeaders });
    return result.headers.__RequestVerificationTokenone;
}

async function reboot(server, user, password) {
    const verificationToken = await login(server, user, password);
    const url = `http://${server}/api/device/control`;
    const headers = {
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        __RequestVerificationToken: verificationToken,
    };
    await client.post(url, '<?xml version:"1.0" encoding="UTF-8"?><request><Control>1</Control></request>', { headers });
}

async function getIpAddress() {
    const data = await axios.get('https://api.ipify.org?format=json')
        .then((res) => res.data)
        .catch((fail) => {
            console.error(fail)
            process.exit()
        })
    console.log(data)
}

async function main() {
    await getIpAddress();
    await reboot(config.ROUTER, config.USER, config.PASSWORD);
    await getIpAddress();
    await reboot(config.ROUTER, config.USER, config.PASSWORD);
    await getIpAddress();
    await reboot(config.ROUTER, config.USER, config.PASSWORD);
}

(async () => {
    await main()
})()

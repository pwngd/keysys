const DEFAULT_EXPIRE_TIME = 60 * 60 * 1000;
const serverStartTime = Date.now();

import Fastify from 'fastify';
import CIDR from 'ip-cidr';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { createReadStream } from 'fs';
import axios from 'axios';
import { MongoClient, ServerApiVersion } from 'mongodb';
let uri = `mongodb+srv://${encodeURIComponent(process.env.DBUSER)}:${encodeURIComponent(process.env.DBPASS)}@cluster0.ar5mwzc.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
let lastKeyGen = 0;

const blockedCIDRs = [
  '3.0.0.0/8',    
  '35.0.0.0/8',   
  '20.0.0.0/8',
  '2400:cb00::/32',
  '2606:4700::/32',
  '2803:f800::/32',
  '2405:b500::/32',
  '2405:8100::/32',
  '2a06:98c0::/29',
  '2c0f:f248::/32',
  '176.59.164.0/22',
  '176.59.168.0/22',
  '176.59.172.0/22',
  '176.59.32.0/19',
  '185.78.92.0/23',
  '176.59.124.0/23',
  '176.59.120.0/22',
  '176.59.118.0/23',
  '176.59.80.0/22',
  '176.59.76.0/22',
  '46.237.44.0/22',
  '176.52.176.0/22',
  '193.110.209.0/24',
  '194.54.32.0/19',
  '195.174.0.0/15',
  '195.174.0.0/17',
  '195.174.128.0/17',
  '195.174.128.0/18',
  '195.175.0.0/17',
  '195.175.0.0/18',
  '195.175.120.0/22',
  '103.102.231.0/24',
  '103.199.80.0/24',
  '103.5.12.0/22',
  '104.167.16.0/24',
  '104.225.253.0/24',
  '104.234.50.0/24'
];
const blockedRanges = blockedCIDRs.map(cidr => new CIDR(cidr));

function isBlockedIP(ip) {
  return blockedRanges.some(cidr => cidr.contains(ip));
}

const fastify = Fastify({trustProxy: true});

// const keys = new Map();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const blacklisted = [];

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});
const dbName = "";
const collectionName="";
let db;
let collection;

class SynAES {
    constructor(key) {
      this.key = key;
        //this.key = Buffer.from(key, 'utf-8')
        switch (Buffer.byteLength(key)) {
            case 16:
                this.gcmalg = "aes-128-gcm"
                break;
            case 24:
                this.gcmalg = "aes-192-gcm"
                break;
            case 32:
                this.gcmalg = "aes-256-gcm"
                break;
            default:
                throw new Error("Invalid Key Length: 16, 24, 32")
        }
    }
    encrypt(data = '', iv = '')  {
        const cipher = crypto.createCipheriv(this.gcmalg, this.key, iv)
        const encryptedBuffer = Buffer.concat([cipher.update(data), cipher.final()])
        return Buffer.concat([encryptedBuffer, cipher.getAuthTag()]).toString("base64")
    }
    decrypt(data = '', iv = '')  {
        data = Buffer.from(data, 'base64');
        const datalen = Buffer.byteLength(data);
        const decipher = crypto.createDecipheriv(this.gcmalg, this.key, iv)
        decipher.setAuthTag(data.slice(datalen - 16, datalen))
        return Buffer.concat([decipher.update(data.slice(0, datalen - 16)), decipher.final()]).toString()
    }
}

const AESKEY = Buffer.from(process.env.AES_KEY, "hex");
const crypt = new SynAES(AESKEY);

function filterPings(content) {
    // Regular expressions to match common pings
    const pingPatterns = [
        /<@!?\d+>/g,  // user mentions like <@1234567890> or <@!1234567890>
        /<@&\d+>/g,   // role mentions like <@&1234567890>
        /@everyone/g, // @everyone
        /@here/g      // @here
    ];

    let filteredContent = content;

    // Replace all pings with an empty string
    pingPatterns.forEach(pattern => {
        filteredContent = filteredContent.replace(pattern, '');
    });

    // Clean up extra spaces
    filteredContent = filteredContent.replace(/\s+/g, ' ').trim();

    return filteredContent;
}

async function webhookMsg(message,link,data) {
    let webhook = link || process.env.WEBHOOK;
    try {
        const payload = data || {
            content: message
        };
        const response = await axios.post(webhook, payload, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
    } catch (error) {
        console.error('Error sending message:', error.response ? error.response.data : error.message);
    }
}

async function fetchFile(file) {
    let data = null;
    try {
        const response = await axios.get(`${process.env.RAW}${file}.lua`, {
            headers: {
                'Authorization': `token ${process.env.PAT}`,
                'Accept': 'application/vnd.github.v3.raw'
            }
        });
        data = response.data;
    } catch (error) {
        console.error('Error fetching file:', error.response ? error.response.data : error.message);
    }
    return data;
}

async function validateLinkBypass(token, hash) {
  const url = `https://publisher.linkvertise.com/api/v1/anti_bypassing?token=${encodeURIComponent(token)}&hash=${encodeURIComponent(hash)}`;

  try {
    const response = await axios.get(url);
    return !!response.data.success; // Ensures a boolean return
  } catch (error) {
    return false;
  }
}

// function getKeysString() {
//     return Array.from(keys.entries())
//         .map(([ip, { key, expires, usage, file, hwid }]) => `KEY: ${key}\n${ip}\n${Math.max(0, expires - Date.now())}ms\n${usage} uses\n${file}\n${hwid}\n`)
//         .join('\n');
// }

async function getKeysString() {
    const keys = await collection.find().toArray();
    return keys
        .map((keyData, index) =>
            `KEY: ${index}\n${keyData.ip}\n${Math.max(0, new Date(keyData.expires) - Date.now())}ms\n${keyData.usage} uses\n${keyData.file}\n${keyData.hwid}\n`
        )
        .join("\n");
}

// setInterval(() => {
//     const now = Date.now();
//     for (const [key, { expires }] of keys.entries()) {
//         if (expires < now) {
//             keys.delete(key);
//         }
//     }
// }, 60000);

async function connectDB() {
  if (db) return db;
  await client.connect();
  db = await client.db("keydb");
  await db.command({ ping: 1 });
  collection = await db.collection("keys");
  console.log("Pinged your deployment. You successfully connected to MongoDB!");
  return db;
}

async function updateKey(key, data) {
    return await collection.updateOne(
        { key },
        { $set: data },
        { upsert: true }
    );
}

async function getKey(key) {
    const result = await collection.findOne({ key });
    if (!result) {
      webhookMsg(`Key didn't exist: ${key}`);
      return null;
    };
    const curTime = Date.now();
    if (result.expires>0&&curTime-result.createdAt>result.expires) {
      webhookMsg(`Expired key used: ${key}`);
      return null;
    };
    webhookMsg(`Key was accessed, result: ${JSON.stringify(result)}`);
    return result;
}

async function deleteKey(key) {
    return collection.deleteOne({ key });
}

async function keyExists(value) {
    const result = await collection.findOne({ value });
    return result !== null;
}

async function incrementUsage(key) {
    return await collection.updateOne(
        { key },
        { $inc: { usage: 1 } }
    );
}

async function getRobloxHeadshot(userId) {
  const url = `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${userId}&size=420x420&format=Png&isCircular=false`;

  try {
    const response = await axios.get(url);
    const data = response.data;

    if (data && data.data && data.data[0]) {
      const headshotUrl = data.data[0].imageUrl;
      return headshotUrl;
    } else {
      throw new Error('No headshot found');
    }
  } catch (err) {
    console.error('Error fetching headshot:', err.message);
    return null;
  }
}

fastify.get('/', async(req,rep)=>{
  return rep.redirect("https://cdn.glitch.global/86c6769d-257a-49f8-95e3-cb3d21f9a700/7512d4bb7116f5816d0fb9aea41d5f65aee6558eed5b6efd43b809c8b25dbd60_3.jpg?v=1743208070461");
});

fastify.get(process.env.ASDF, async (request, reply) => {
    const curTime = Date.now();
    if ((curTime-lastKeyGen)<2000) {
      webhookMsg(`Keys generated too fast ${request.ip}`);
      return reply.code(403).send('forbidden. stop mass gen keys with proxies :(');
    }
    lastKeyGen = curTime;
    const { hash,ref } = request.query;
    const referer = request.headers['referer'];
    const userAgent = request.headers['user-agent'];
    const ip = request.ip;
  
    if (hash==null&&ref!=="lootlabs") return reply.type('text/plain').send("Invalid linkvertise hash, do not use bypasser, if this keeps happening contact the discord: https://discord.gg/dDZ8XMQUrx");
  
    let antibypass = true;
  
//     if (referer==="https://bypass.city/"||referer==="https://bypass.vip/"||referer==="https://bypassunlock.com/") {
//       webhookMsg(`Blatant bypass! ${ip} ${hash}`);
//       return reply.type("invalid hash");
//     }
    
//     if (ref === "lootlabs") {
//       antibypass = true;
//     } else {
//       antibypass = await validateLinkBypass(process.env.TOKEN,hash);
//     }
  
//     if (antibypass===false&&hash!==process.env.ADMIN_HASH) {
//       webhookMsg(`Bypass detected! IP: ${ip}, Hash: ${hash}`);
//       return reply.type('text/plain').send("Bypass detected, contact discord for support: https://discord.gg/dDZ8XMQUrx");
//     }
  
    if (await keyExists(ip)) {
      webhookMsg(`IP already had a key: ${ip}, Hash: ${hash}`);
      return reply.type('text/plain').send("ip already has valid key, join discord for support: https://discord.gg/dDZ8XMQUrx")
    }
    const key = crypto.randomBytes(16).toString('hex');
    let file = "";
    if (request.query.f == "xertion") {file = "xertion"};
    if (request.query.f == "bloodzone") {file = "bloodzone"};
    if (file!="xertion"&&file!="bloodzone") return reply.code(400).send("Invalid file type");
    
    if (hash===process.env.ADMIN_HASH&&request.query.expires) {
      await updateKey(key, { ip: "", createdAt: Date.now(), expires:parseInt(request.query.expires||DEFAULT_EXPIRE_TIME)||DEFAULT_EXPIRE_TIME, usage: 0, file:file, hwid:"", referrer:referer, userAgent:userAgent });
    } else {
      await updateKey(key, { ip: ip, createdAt: Date.now(), expires:DEFAULT_EXPIRE_TIME, usage: 0, file:file, hwid:"", referrer:referer, userAgent:userAgent });
    }
  
    webhookMsg(`New key: ${key}, IP: ${ip}, File: ${file}`);
    return reply.type('text/plain').send(`your key is ${key}`);
});

fastify.get('/file', async (request, reply) => {
    const { key } = request.query;
    const ip = request.ip;
    const cache = await getKey(key);
  
    if (blacklisted.includes(ip)) {
      webhookMsg(`Blacklisted ip requested file: ${ip}`);
      return reply.code(404)
    };
    if (!key) return reply.code(404);
  
    if (cache!==null&&cache.ip=="") updateKey(key,{ip:ip});
  
    if (cache===null || cache.ip !== ip) {
        webhookMsg(`Invalid key used: ${key}, IP: ${ip}`);
        return reply.code(403).send({ error: 'Invalid or expired key' });
    }
    
    webhookMsg(`File accessed with key: ${key}. Usages: ${cache.usage}.`);
    const fileData = await fetchFile(cache.file);
    return reply.type('text/plain').send(fileData);
});

fastify.get('/admin', async(req,rep)=>{
  const { key, genaes, bankey } = req.query;
  if (key !== process.env.ADMIN) {
    return rep.code(404).send();
  }
  if (genaes && genaes==="true") {
    return rep.send([crypto.randomBytes(32).toString("hex"),crypto.randomBytes(16).toString("hex")]);
  }
  if (bankey) {
    await collection.deleteOne({key:bankey});
    return rep.send(`Banned key ${bankey}`);
  }
  return rep.send(await getKeysString());
});

fastify.get(process.env.ROUTE1, async(req,rep)=>{
  // webhookMsg(`${req.query['1a86']}`);
  // if (req.query['1a86']!==process.env.SIGMA) {
  //   return rep.type('text/plain').send(crypto.randomBytes(16).toString('hex'));
  // }
  const { key } = req.query;
  const hwid = req.query[process.env.HWID];
  const ip = req.ip;
  const cache = await getKey(key);
  //const iv = crypto.randomBytes(12);
  if (!hwid) {
    webhookMsg(`No HWID Provided! ${key}, IP ${ip}`);
    return rep.type('text/plain').send('invalid');
  }
  if (cache!==null&&cache.ip==="none") await updateKey(key,{ip:ip});
  if (cache===null || cache.ip!==ip) {
      webhookMsg(`Invalid key entered on runtime: ${key}, IP: ${ip}, HWID: ${hwid}`);
      return rep.type('text/plain').send('invalid');
  }
  if (cache.hwid!==""&&cache.hwid!==hwid) {
    webhookMsg(`HWID did not match initial! ${key}, IP: ${ip}`);
    return rep.type('text/plain').send('invalid');
  }
  await incrementUsage(key);
  await updateKey(key, {hwid:hwid});
  webhookMsg(`Script accessed with key: ${key}, IP: ${ip}, HWID: ${hwid}, Usages: ${cache.usage}`);
  // const secret = crypt.encrypt(process.env.SECRET,iv);
  // return rep.type('text/plain').send(secret);
  switch (cache.file) {
    case "xertion":
      return rep.type('text/plain').send(process.env.SECRET);
      break;
    case "bloodzone":
      return rep.type('text/plain').send(process.env.SECRET2);
      break;
    default:
      return rep.type('text/plain').send('invalid')
      break;
  }
});

fastify.get('/update', async(req,rep)=>{
  const { key } = req.query;
  const ip = req.ip;
  const cache = await getKey(key);
  if (cache!==null&&cache.ip==="") await updateKey(key,{ip:ip});
  if (cache===null || cache.ip!==ip) {
      webhookMsg(`Invalid key used: ${key}, IP: ${ip}`);
      return rep.type('text/plain').send('invalid');
  }
  const fileData = await fetchFile("update");
  return rep.type('text/plain').send(fileData);
});

fastify.post('/telemetry', async(req,rep)=>{
  try {
    const data = req.body;
    console.log(data);
    if (data.type!==null&&data.type==="chat") {
      webhookMsg(null, process.env.WEBHOOK2, {
        content: filterPings(data.message),
        username: data.sender,
        avatar_url: await getRobloxHeadshot(data.senderid)
      });
    } else {
      webhookMsg(`**Telemetry (IP:${req.ip}):** \`\`\`json\n${JSON.stringify(data)}\n\`\`\``);
    }
  } catch (err) {
    console.warn(err);
  }
});

(async ()=>{
  fastify.register(async function cloudBlocker(fastify, opts) {
    fastify.addHook('onRequest', async (request, reply) => {
      const ip = request.headers['x-forwarded-for'] || request.ip;

      if (isBlockedIP(ip)) {
        fastify.log.info(`Blocked cloud IP: ${ip}`);
        webhookMsg(`Blocked suspicious IP: ${ip}`);
        reply.code(403).send({ message: 'Access denied.' });
      }
    });
  });
  
  await connectDB();
  fastify.listen({ port: 3000, host: '0.0.0.0' }, (err, address) => {
    if (err) {
        console.error(err);
        process.exit(1);
    }
    console.log(`Server running at ${address}`);
  });
  async function stat(){
    const curTime = Date.now();
    const keysLastHour = await collection.countDocuments({
        createdAt: { $gte: curTime-(3600*1000) }
    });
    const totalKeys = await collection.countDocuments();
    const serverUptime = (curTime - serverStartTime) / (1000 * 60 * 60);
    //const serverStatus = await db.admin().serverStatus();
    //const serverStatStr = JSON.stringify(serverStatus,null,2);
    webhookMsg(`Server check in!\ntotal keys:${totalKeys}\nuptime:${serverUptime}\nkeys last hour:${keysLastHour}`);
    //webhookMsg(`DB server status trimmed: ${serverStatStr.substring(0,1700)}`);
  }
  setTimeout(stat, 5000);
  setInterval(stat, 30 * 60 * 1000);
})();
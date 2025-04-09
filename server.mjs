// ================= IMPORTS =================
import dotenv from 'dotenv';
import Fastify from 'fastify';
import CIDR from 'ip-cidr';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import axios from 'axios';
import { MongoClient, ServerApiVersion } from 'mongodb';
import fastifyStatic from '@fastify/static';
import fastifyRateLimit from '@fastify/rate-limit';
import fastifyView from '@fastify/view';
import ejs from 'ejs';

dotenv.config();

// ================= CONSTANTS =================
const DEFAULT_EXPIRE_TIME = 60 * 60 * 1000;
const serverStartTime = Date.now();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const fastify = Fastify({ trustProxy: true });
const files = ["xertion", "bloodzone"];
const blacklisted = [];
let lastKeyGen = 0;

let db;
let collection;

const client = new MongoClient(`mongodb+srv://${encodeURIComponent(process.env.DBUSER)}:${encodeURIComponent(process.env.DBPASS)}@cluster0.ar5mwzc.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true }
});

const blockedCIDRs = [ /* ...list omitted for brevity... */ ];
const blockedRanges = blockedCIDRs.map(cidr => new CIDR(cidr));

// ================= HELPERS =================
function isBlockedIP(ip) {
  return blockedRanges.some(cidr => cidr.contains(ip));
}

function millisecondsToTime(ms) {
  const hours = Math.floor(ms / (1000 * 60 * 60));
  const minutes = Math.floor((ms % (1000 * 60 * 60)) / (1000 * 60));
  const seconds = Math.floor((ms % (1000 * 60)) / 1000);
  return `${hours}h ${minutes}m ${seconds}s`;
}

function filterPings(content) {
  const pingPatterns = [/<@!?\d+>/g, /<@&\d+>/g, /@everyone/g, /@here/g];
  let filteredContent = content;
  pingPatterns.forEach(pattern => {
    filteredContent = filteredContent.replace(pattern, '');
  });
  return filteredContent.replace(/\s+/g, ' ').trim();
}

async function webhookMsg(message, link, data) {
  let webhook = link || process.env.WEBHOOK;
  try {
    const payload = data || { content: message };
    await axios.post(webhook, payload, {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Error sending message:', error.response ? error.response.data : error.message);
  }
}

async function fetchFile(file) {
  try {
    const response = await axios.get(`${process.env.RAW}${file}.lua`, {
      headers: {
        'Authorization': `token ${process.env.PAT}`,
        'Accept': 'application/vnd.github.v3.raw'
      }
    });
    return response.data;
  } catch (error) {
    console.error('Error fetching file:', error.response ? error.response.data : error.message);
    return null;
  }
}

async function validateLinkBypass(token, hash) {
  const url = `https://publisher.linkvertise.com/api/v1/anti_bypassing?token=${encodeURIComponent(token)}&hash=${encodeURIComponent(hash)}`;
  try {
    const response = await axios.get(url);
    return !!response.data.success;
  } catch (error) {
    return false;
  }
}

async function connectDB() {
  if (db) return db;
  await client.connect();
  db = await client.db("keydb");
  await db.command({ ping: 1 });
  collection = await db.collection("keys");
  console.log("Connected to MongoDB!");
  return db;
}

async function updateKey(key, data) {
  return await collection.updateOne({ key }, { $set: data }, { upsert: true });
}

async function getKey(key) {
  const result = await collection.findOne({ key });
  if (!result) {
    webhookMsg(`Key didn't exist: ${key}`);
    return null;
  }
  const curTime = Date.now();
  if (result.expires > 0 && curTime - result.createdAt > result.expires) {
    webhookMsg(`Expired key used: ${key}`);
    return null;
  }
  webhookMsg(`Key accessed: ${JSON.stringify(result)}`);
  return result;
}

async function keyExists(value) {
  const result = await collection.findOne({ value });
  return result !== null;
}

async function incrementUsage(key) {
  return await collection.updateOne({ key }, { $inc: { usage: 1 } });
}

async function getKeysString() {
  const keys = await collection.find().toArray();
  return keys.map(keyData => `KEY: ${keyData.key}\n${keyData.ip}\n${Math.max(0, new Date(keyData.expires) - Date.now())}ms\n${keyData.usage} uses\n${keyData.file}\n${keyData.hwid}\n`).join("\n");
}

async function getRobloxHeadshot(userId) {
  const url = `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${userId}&size=420x420&format=Png&isCircular=false`;
  try {
    const response = await axios.get(url);
    if (response.data && response.data.data && response.data.data[0]) {
      return response.data.data[0].imageUrl;
    } else {
      throw new Error('No headshot found');
    }
  } catch (err) {
    console.error('Error fetching headshot:', err.message);
    return null;
  }
}

// ================= PLUGINS ================
await fastify.register(fastifyRateLimit, {
  max: 300,
  timeWindow: '1 minute'
});

await fastify.register(fastifyStatic, {
  root: join(__dirname, 'assets'),
  prefix: '/assets/',
});

await fastify.register(fastifyView, {
  root: join(__dirname, 'view'),
  engine: {
    ejs: ejs,
  }
});

await fastify.register(async function cloudBlocker(fastify, opts) {
  fastify.addHook('onRequest', async (request, reply) => {
    const ip = request.headers['x-forwarded-for'] || request.ip;

    if (isBlockedIP(ip)) {
      fastify.log.info(`Blocked cloud IP: ${ip}`);
      webhookMsg(`Blocked suspicious IP: ${ip}`);
      reply.code(403).send({ message: 'Access denied.' });
    }
  });
});

await connectDB(); // CONNECT TO DATABASE!!!

// ================= ROUTES =================
fastify.setNotFoundHandler({
  preHandler: (req, reply, done) => {
    reply.status(404).viewAsync('message', { title: `Error 404 - Not Found`, message: `Resource could not be found.` });
    done();
  }
},async (request, reply)=>{
  return reply.status(404).viewAsync('message', { title: `Error 404 - Not Found`, message: `Resource could not be found.` });
});

fastify.setErrorHandler(async (error, request, reply)=>{
  return reply.viewAsync('message', { title: `Error 403 - Forbidden`, message: `You don't have permission to access this resource.` });
});

fastify.get('/', async(req,rep)=>{
  return rep.code(200).viewAsync('discord');
});

fastify.get('/status', async(req,rep)=>{
  return rep.viewAsync('message', { title: `Status`, message: `Key system: Working. (Uptime: ${millisecondsToTime(Date.now() - serverStartTime)})` });
});

fastify.get('/gen', {
  config: {
    rateLimit: {
      max: 1,
      timeWindow: '1 minute'
    }
  },
  schema: {
    querystring: {
      type: 'object',
      properties: {
        hash: { type: 'string' },
        ref: { type: 'string' },
        f: { type: 'string' }
      },
      required: ['f'] // or ['hash', 'ref'] if you want them to be mandatory
    }
  }
}, async (request, reply) => {
    const curTime = Date.now();
    if ((curTime-lastKeyGen)<2000) {
      webhookMsg(`Keys generated too fast ${request.ip}`);
      for (let i = 1; i <= 30; i++) {
        reply.header(`detected-by-lua-armor_${i}`, 'detected-by-lua-armor');
      }
      return reply.sendFile('detection.mp4');
      // return reply.code(403).send('forbidden');
    }
    lastKeyGen = curTime;
    const { hash, ref } = request.query;
    const referer = request.headers['referer'];
    const userAgent = request.headers['user-agent'];
    const ip = request.ip;
  
    if (hash==null&&ref!=="lootlabs") return reply.type('text/plain').send("Invalid linkvertise hash, do not use bypasser, if this keeps happening contact the discord: https://discord.gg/dDZ8XMQUrx");
  
    let antibypass = false;
  
    if (referer==="https://bypass.city/"||referer==="https://bypass.vip/"||referer==="https://bypassunlock.com/") {
      webhookMsg(`Blatant bypass! ${ip} ${hash}`);
      return reply.type("invalid hash");
    }
    
    if (ref === "lootlabs") {
      antibypass = true;
    } else {
      antibypass = await validateLinkBypass(process.env.TOKEN,hash);
    }
  
    if (antibypass===false&&hash!==process.env.ADMIN_HASH) {
      webhookMsg(`Bypass detected! IP: ${ip}, Hash: ${hash}`);
      return reply.type('text/plain').send("Bypass detected, contact discord for support: https://discord.gg/dDZ8XMQUrx");
    }
  
    if (await keyExists(ip)) {
      webhookMsg(`IP already had a key: ${ip}, Hash: ${hash}`);
      return reply.type('text/plain').send("ip already has valid key, join discord for support: https://discord.gg/dDZ8XMQUrx")
    }
    const key = crypto.randomBytes(16).toString('hex');
    let file = "";
    if (files.includes(request.query.f)) {
      file = request.query.f;
    } else {
      return reply.code(400).send("Invalid file type");
    }
    
    if (hash===process.env.ADMIN_HASH&&request.query.expires) {
      await updateKey(key, { ip: "", createdAt: Date.now(), expires:parseInt(request.query.expires||DEFAULT_EXPIRE_TIME)||DEFAULT_EXPIRE_TIME, usage: 0, file:file, hwid:"", referrer:referer, userAgent:userAgent });
    } else {
      await updateKey(key, { ip: ip, createdAt: Date.now(), expires:DEFAULT_EXPIRE_TIME, usage: 0, file:file, hwid:"", referrer:referer, userAgent:userAgent });
    }
  
    webhookMsg(`New key: ${key}, IP: ${ip}, File: ${file}`);
    return reply.viewAsync("gen", { key: key, file: file });
});

fastify.get('/file', {
  schema: {
    headers: {
      type: 'object',
      required: ['user-agent'],
      properties: {
        'user-agent': { type: 'string' }
      }
    }
  }
}, async (request, reply) => {
    if (request.headers['user-agent'].trim().toLowerCase() !== "roblox/wininet") {
      return reply.viewAsync('forbidden', { title: `Error 403 - Forbidden`, message: `You don't have permission to access this resource.` });
    }
    const { key } = request.query;
    const ip = request.ip;
    const cache = await getKey(key);
  
    if (blacklisted.includes(ip)) {
      webhookMsg(`Blacklisted ip requested file: ${ip}`);
      return reply.callNotFound();
    };
    if (!key) return reply.callNotFound();
  
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
    return rep.callNotFound();
  }
  if (genaes && genaes==="true") {
    return rep.send([crypto.randomBytes(32).toString("hex"),crypto.randomBytes(16).toString("hex")]);
  }
  if (bankey) {
    await collection.deleteOne({key:bankey});
    return rep.send(`Banned key ${bankey}`);
  }
  return rep.viewAsync('admin');
});

fastify.get('/40aea041', async(req,rep)=>{
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
  const secrets = {xertion:"d93997e0d2bcee704a9d2fc7f0a0ca34", bloodzone:"6391df23ac30c0b5a4f98ce67251251f"};
  return rep.type('text/plain').send(secrets[cache.file.toLowerCase()]);
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

// ================= SERVER INIT =================
fastify.listen({ port: process.env.PORT, host: '0.0.0.0', trustProxy: true, logger: false, exposeHeaderrs: false }, (err, address) => {
  if (err) {
      console.error(err);
      process.exit(1);
  }
  console.log(`Server running at ${address}`);
});

// ========= STATISTICS WEBHOOK LOOP ===========
setInterval(async ()=>{
  const curTime = Date.now();
  const keysLastHour = await collection.countDocuments({
      createdAt: { $gte: curTime-(3600*1000) }
  });
  const totalKeys = await collection.countDocuments();
  const serverUptime = millisecondsToTime(curTime - serverStartTime);
  //const serverStatus = await db.admin().serverStatus();
  //const serverStatStr = JSON.stringify(serverStatus,null,2);
  webhookMsg(`Server check in!\ntotal keys:${totalKeys}\nuptime:${serverUptime}\nkeys last hour:${keysLastHour}`);
  //webhookMsg(`DB server status trimmed: ${serverStatStr.substring(0,1700)}`);
}, 30 * 60 * 1000);
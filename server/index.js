import express from 'express';
import cors from 'cors';
import { WebSocketServer } from 'ws';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const app = express();
app.use(cors());
app.use(express.json({limit:'256kb'}));
const PORT = Number(process.env.PORT || 8787);
const DATA = process.env.ESHGHAM_DATA || './data';
fs.mkdirSync(DATA,{recursive:true});
const stateFile=path.join(DATA,'state.json');
let state=fs.existsSync(stateFile)?JSON.parse(fs.readFileSync(stateFile,'utf8')):{pairs:{}};
const save=()=>fs.writeFileSync(stateFile,JSON.stringify(state));
const sha256=(v)=>crypto.createHash('sha256').update(v).digest('hex');
const hmac=(key,v)=>crypto.createHmac('sha256',key).update(v).digest('hex');
const pair=(id)=>state.pairs[id];
function auth(req){const id=String(req.headers['x-pair-id']||'');const ts=String(req.headers['x-timestamp']||'');const sig=String(req.headers['x-signature']||'');const p=pair(id);if(!p||!ts||Math.abs(Date.now()-Number(ts))>120000)return null;return hmac(p.secret,`${req.method}:${req.path}:${ts}`)===sig?p:null;}
app.get('/health',(_,res)=>res.json({ok:true,service:'eshgam-relay',version:1}));
app.post('/pair/register',(req,res)=>{const {pairId,secretHash,deviceId}=req.body||{};if(!/^[a-f0-9]{32}$/i.test(String(pairId))||!secretHash||!deviceId)return res.status(400).json({error:'invalid'});let p=pair(pairId);if(!p){p={secret:secretHash,devices:[],createdAt:Date.now()};state.pairs[pairId]=p;}if(p.secret!==secretHash)return res.status(403).json({error:'pair_secret_mismatch'});if(!p.devices.includes(deviceId)){if(p.devices.length>=2)return res.status(403).json({error:'two_devices_only'});p.devices.push(deviceId);save();}res.json({ok:true,devices:p.devices.length});});
const wss=new WebSocketServer({noServer:true});
const sockets=new Map();
wss.on('connection',(ws,req)=>{const u=new URL(req.url,'http://localhost');const id=u.searchParams.get('pairId');const device=u.searchParams.get('deviceId');const ts=u.searchParams.get('timestamp');const sig=u.searchParams.get('signature');const p=pair(id);if(!p||!device||!ts||Math.abs(Date.now()-Number(ts))>120000||hmac(p.secret,`WS:${id}:${device}:${ts}`)!==sig||!p.devices.includes(device)){ws.close(1008,'unauthorized');return;}const key=`${id}:${device}`;sockets.set(key,ws);ws.on('message',(raw)=>{if(raw.length>1024*1024){ws.close(1009);return;}let msg;try{msg=JSON.parse(raw.toString())}catch{return;}if(!msg||typeof msg.type!=='string')return;for(const d of p.devices){if(d===device)continue;const peer=sockets.get(`${id}:${d}`);if(peer?.readyState===1)peer.send(JSON.stringify(msg));}});ws.on('close',()=>sockets.delete(key));});
const server=app.listen(PORT,()=>console.log(`Eshgam relay listening on ${PORT}`));
server.on('upgrade',(req,socket,head)=>{if(new URL(req.url,'http://localhost').pathname!=='/ws')return socket.destroy();wss.handleUpgrade(req,socket,head,ws=>wss.emit('connection',ws,req));});

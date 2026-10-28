/* Electribe 2 ueber Web MIDI - Protokollschicht.
   Rahmen: F0 42 3n 00 01 24 <Funktion> <7-bit-gepackte Nutzdaten> F7
   Nutzdaten: 32-Bit-Woerter, Little Endian, Korgs 8-in-7-Packung.
   Belege: hacktribe/scripts/e2_syx_codec.py,
           kuhlers-gelumpe src/protocol.mjs, src/sender.mjs, src/remote.mjs,
           data/panel.mjs, data/exec.mjs, data/map/screen.mjs */

export const FN = { INFO:0x60, READ:0x61, WBEGIN:0x62, WDATA:0x63,
                    FLASHREAD:0x64, FILEREAD:0x65, FILEBEGIN:0x66, EXEC:0x6f };
export const RE = { INFO:0x68, READ:0x69, WBEGIN:0x6a, WDATA:0x6b,
                    FLASHREAD:0x6c, FILEREAD:0x6d, FILEBEGIN:0x6e, EXEC:0x70 };
export const STATUS = ["in Ordnung","Pruefsumme stimmt nicht","verweigert",
  "ausserhalb des erlaubten Bereichs","Flash-Funktion meldet keinen Erfolg",
  "Rueckgelesenes weicht ab","Kartenfehler"];
/* Was die Firmware laut INFO kann. */
export const FLAG = { READ:0x01, WRITE:0x02, CRC:0x04, FLASH:0x08,
                      FILE:0x10, PLUGIN:0x20, EXEC:0x40, SAMPLE:0x80 };
export const MAX_BLOCK = 32768;
/* Bit 31 eines FILE-Offsets: ORIGINAL.BIN neben SYSTEM.VSB. */
export const FILE_OTHER = 0x80000000;
export const FILE_LIMIT = 0x200100;

/* Korgs 8-in-7: je 7 Nutzbytes ein Kopfbyte mit deren obersten Bits. */
export function pack(bytes){
  const out=[];
  for(let i=0;i<bytes.length;i+=7){
    const chunk=bytes.subarray(i,Math.min(i+7,bytes.length));
    let head=0;
    for(let k=0;k<chunk.length;k++) head|=((chunk[k]&0x80)>>7)<<k;
    out.push(head);
    for(const b of chunk) out.push(b&0x7f);
  }
  return Uint8Array.from(out);
}
export function unpack(seven){
  const out=[];
  for(let i=0;i<seven.length;i+=8){
    const head=seven[i];
    for(let k=0;k<7 && i+1+k<seven.length;k++) out.push(seven[i+1+k]|(((head>>k)&1)<<7));
  }
  return Uint8Array.from(out);
}
/* CRC-32 wie zlib, Polynom 0xEDB88320 */
const CRCT=(()=>{const t=new Uint32Array(256);for(let n=0;n<256;n++){let c=n;for(let k=0;k<8;k++)c=c&1?0xEDB88320^(c>>>1):c>>>1;t[n]=c>>>0;}return t;})();
export function crc32(b){let c=0xFFFFFFFF;for(let i=0;i<b.length;i++)c=CRCT[(c^b[i])&0xff]^(c>>>8);return (c^0xFFFFFFFF)>>>0;}
export const words=(...v)=>{const b=new Uint8Array(v.length*4);const d=new DataView(b.buffer);v.forEach((x,i)=>d.setUint32(i*4,x>>>0,true));return b;};
export const readWords=(b,n)=>{const d=new DataView(b.buffer,b.byteOffset);return Array.from({length:n},(_,i)=>d.getUint32(i*4,true));};
export const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,"0")).join("");

/* ---- Adressen ---------------------------------------------------------- */
/* Abbild laedt auf 0xC0000000, die Datei hat 0x100 Byte Kopf davor. */
export const BASE=0xC0000000, HDR=0x100;
export const ramToFile = a => a - BASE + HDR;
/* Stub-Puffer fuer EXEC und die Cache-Routine der Firmware (data/exec.mjs). */
export const EXEC_AT=0xC1000000, EXEC_SIZE=0x400;
export const ICACHE={addr:0xC00016A4,length:0x34};
/* Die Bytes der Cache-Routine. In Korgs Original, Hacktribe und unserem Bau gleich. */
export const ICACHE_BYTES="150f07ee0000a0e10000a0e10000a0e10000a0e10000a0e10000a0e10000a0e10000a0e1100f11ee010a80e3100f01ee0ef0a0e1";
/* Fernsteuerung: die Laufzeit legt "REMT" und dahinter die Postfachadresse ab. */
export const REMT={from:0xC018D000,to:0xC018FF00,sign:0x544D4552};
export const REMOTE={MARK:0xA5000000, KEY:1, ENCODER:2, OS_WAIT:0xC0000B78, TRIES:50};
/* Displaybild im RAM: 8 Seiten zu 128 Spalten, Bit 0 oben. */
export const DISPLAY={addr:0xC031B310,size:1024,w:128,h:64};
/* Name der Datei, die SOFTWARE UPDATE oeffnet. Nur mit dem Patch updatename.py:
   dann zeigen die drei Literal-Pools der Firmware hierher statt auf ihre feste
   Zeichenkette. Der Name gilt bis zum Neustart. */
/* ---- Pattern im Arbeitsspeicher ---------------------------------------
   Das laufende Pattern liegt als Arbeitskopie im RAM (im Emulator gemessen,
   tools/sonden/klemme.py). Aufbau: Kopf 0x800, dann 16 Parts zu 0x330, jeder
   48 Byte Parameter und 64 Steps zu 12 Byte. Ein Step belegt acht davon:
   on, gate, velocity, trigger, vier Notenbytes. Die Bytes +8 bis +11 sind frei
   und halten mit dem Achttakte-Patch on, gate, velocity und die Note der
   Takte 5 bis 8 - Step 64+N in den freien Bytes von Step N. Einen eigenen
   Trigger haben die Takte 5 bis 8 nicht, den erben sie von den Takten 1 bis 4. */
export const PATTERN={addr:0xC06B279C,size:0x4000,kopf:0x800,part:0x330,
                      params:48,step:12,parts:16,steps:64,frei:8};
export const LAENGE_OFF=0x25;            // Blockoffset des Laengenfelds, 0..7 = 1..8 Takte

export const UPDATE_NAME={addr:0xC00DBD00,size:0x40};
/* Die drei Literal-Pools, die die Adresse des Update-Dateinamens laden. */
export const UPDATE_POOLS=[0xC0030B40,0xC003AA64,0xC003AE8C];
export const UPDATE_KORG=0xC00A482C;      // Korgs feste Zeichenkette "/SYSTEM.VSB"
export const UPDATE_NAME_ALT=0xC01AE000;  // erster Pufferplatz, falsch: wird beim Start ueberschrieben
/* Startbild in der Datei: 8 Seiten zu 128 Spalten, Bit 7 oben. */
export const SPLASH={file:0xF9954,size:1024,w:128,h:64};

/* ---- Bedienteil (kuhlers-gelumpe data/panel.mjs, im Emulator gemessen) --- */
export const BUTTONS=[
  ["rec","REC",0x00],["stop","STOP",0x01],["play","PLAY",0x02],["tap","TAP",0x03],
  ["gateArp","GATE ARP",0x04],["touchScale","TOUCH SCALE",0x05],["masterFx","MASTER FX",0x06],
  ["mfxHold","MFX HOLD",0x07],["editLeft","◄ EDIT",0x08],["menu","MENU",0x09],
  ["shift","SHIFT",0x0a],["partDec","◄ PART",0x0b],["editRight","EDIT ►",0x0c],
  ["exit","EXIT",0x0d],["write","WRITE",0x0e],["partInc","PART ►",0x0f],
  ["partMute","PART MUTE",0x10],["partErase","PART ERASE",0x11],["lpf","LPF",0x12],
  ["trigger","TRIGGER",0x13],["hpf","HPF",0x14],["sequencer","SEQUENCER",0x15],
  ["bpf","BPF",0x16],["keyboard","KEYBOARD",0x17],["chord","CHORD",0x18],
  ["stepJump","STEP JUMP",0x19],["mfxSend","MFX SEND",0x1a],["patternSet","PATTERN SET",0x1b],
  ["bar1","BAR 1",0x1c],["bar2","BAR 2",0x1d],["bar3","BAR 3",0x1e],["bar4","BAR 4",0x1f],
  ["ampEg","AMP EG",0x20],["ifxOn","IFX ON",0x21],["touch","TOUCHPAD",0x22],
].map(([id,label,index])=>({id,label,index}));
export const ENCODERS=[
  ["value","VALUE / PATTERN",0],["osc","SAMPLE / OSC",1],["cutoff","CUTOFF",2],
  ["modType","MOD. TYPE",3],["ifxType","IFX TYPE",4],
].map(([id,label,index])=>({id,label,index}));

export class E2 {
  constructor(){ this.inp=null; this.out=null; this.channel=0; this.id=0x24;
                 this.pending=null; this.log=()=>{}; this.maxBlock=MAX_BLOCK; this.flags=0; }
  async open(){
    const a=await navigator.requestMIDIAccess({sysex:true});
    this.access=a;
    return {inputs:[...a.inputs.values()],outputs:[...a.outputs.values()]};
  }
  use(inp,out){
    this.inp=inp; this.out=out;
    inp.onmidimessage=e=>{
      const d=e.data;
      if(d[0]!==0xF0) return;
      this.log("<- "+hex(d).slice(0,80)+(d.length>40?"…":""));
      if(this.pending) this.pending(d);
    };
  }
  send(bytes){ this.log("-> "+hex(bytes).slice(0,80)); this.out.send(bytes); }
  wait(ms=6000){
    return new Promise((res,rej)=>{
      const t=setTimeout(()=>{this.pending=null;rej(new Error("Zeit abgelaufen - antwortet das Geraet? BLECH-SysEx vorhanden?"))},ms);
      this.pending=d=>{clearTimeout(t);this.pending=null;res(d)};
    });
  }
  /** Korgs Geraetesuche, unabhaengig von BLECH. */
  async search(){
    this.send(Uint8Array.from([0xF0,0x42,0x50,0x00,0x00,0xF7]));
    const r=await this.wait(2000);
    if(!(r[1]===0x42&&r[2]===0x50&&r[3]===0x01)) throw new Error("keine Suchantwort");
    this.channel=r[4]; this.id=r[6];
    return {channel:r[4], id:r[6], version:`${r[10]}.${r[11]}`,
            modell:r[6]===0x24?"Electribe 2 Sampler":r[6]===0x23?"Electribe 2 Synth":`unbekannt 0x${r[6].toString(16)}`};
  }
  frame(fn,payload=new Uint8Array(0)){
    return Uint8Array.from([0xF0,0x42,0x30|(this.channel&0xf),0x00,0x01,this.id,fn,...pack(payload),0xF7]);
  }
  async cmd(fn,payload,expect,ms){
    this.send(this.frame(fn,payload));
    const r=await this.wait(ms);
    if(r[6]!==expect) throw new Error(`Antwort 0x${r[6].toString(16)} statt 0x${expect.toString(16)}`);
    return unpack(r.subarray(7,r.length-1));
  }
  /** Prueft das Statuswort und gibt die Woerter zurueck. */
  check(p,n,was){
    const w=readWords(p,n);
    if(w[0]!==0) throw new Error(`${was}: ${STATUS[w[0]]||w[0]}`);
    return w;
  }
  async info(){
    const p=await this.cmd(FN.INFO,new Uint8Array(0),RE.INFO);
    const w=readWords(p,5);
    this.flags=w[2]; this.maxBlock=Math.min(w[3]||MAX_BLOCK,MAX_BLOCK);
    return {status:w[0], version:w[1], flags:w[2], maxBlock:w[3], tableCrc:w[4],
            kann:{lesen:!!(w[2]&FLAG.READ),schreiben:!!(w[2]&FLAG.WRITE),crc:!!(w[2]&FLAG.CRC),
                  flash:!!(w[2]&FLAG.FLASH),datei:!!(w[2]&FLAG.FILE),plugin:!!(w[2]&FLAG.PLUGIN),
                  code:!!(w[2]&FLAG.EXEC),sample:!!(w[2]&FLAG.SAMPLE)}};
  }

  /* ---- RAM ---- */
  async read(addr,len){
    if(len<1||len>this.maxBlock) throw new Error(`Laenge 1 bis ${this.maxBlock}`);
    const p=await this.cmd(FN.READ,words(addr,len),RE.READ);
    const w=this.check(p,4,"READ");
    const data=p.subarray(16,16+w[2]);
    if(crc32(data)!==w[3]) throw new Error("READ: CRC der Antwort stimmt nicht");
    return data;
  }
  async readAll(addr,len,onProgress){
    const out=new Uint8Array(len);
    for(let o=0;o<len;o+=this.maxBlock){
      const n=Math.min(this.maxBlock,len-o);
      out.set(await this.read(addr+o,n),o);
      onProgress?.(o+n,len);
    }
    return out;
  }
  async write(addr,data){
    if(data.length<1||data.length>this.maxBlock) throw new Error(`Laenge 1 bis ${this.maxBlock}`);
    const c=crc32(data);
    this.check(await this.cmd(FN.WBEGIN,words(addr,data.length,c),RE.WBEGIN),3,"WRITE BEGIN");
    const w=this.check(await this.cmd(FN.WDATA,data,RE.WDATA),4,"WRITE DATA");
    if(w[3]!==c) throw new Error("WRITE: das Geraet las andere Bytes zurueck");
    return w;
  }
  async writeAll(addr,data,onProgress){
    for(let o=0;o<data.length;o+=this.maxBlock){
      const n=Math.min(this.maxBlock,data.length-o);
      await this.write(addr+o,data.subarray(o,o+n));
      onProgress?.(o+n,data.length);
    }
  }
  async flashRead(addr,len){
    const p=await this.cmd(FN.FLASHREAD,words(addr,len),RE.FLASHREAD);
    const w=this.check(p,4,"FLASH READ");
    return p.subarray(16,16+w[2]);
  }

  /* ---- Datei auf der Karte (KORG/<ordner>/System/) ---------------------- */
  /** Ein Stueck der Update-Datei; Laenge 0 fragt nur nach der Groesse. */
  async fileRead(offset,len){
    const p=await this.cmd(FN.FILEREAD,words(offset>>>0,len),RE.FILEREAD,20000);
    const w=readWords(p,5);
    if(w[0]!==0){ const e=new Error(`FILE READ: ${STATUS[w[0]]||w[0]}`); e.status=w[0]; throw e; }
    const bytes=p.subarray(20,20+w[2]);
    if(w[2]!==len) throw new Error(`FILE READ: ${w[2]} Byte statt ${len}`);
    if(len && crc32(bytes)!==w[3]) throw new Error("FILE READ: CRC stimmt nicht");
    return {offset:w[1], bytes, size:w[4]};
  }
  /** Groesse der Datei auf der Karte, 0 wenn keine da ist. */
  async fileSize(other=false){
    try{ return (await this.fileRead(other?FILE_OTHER:0,0)).size; }
    catch(e){ if(e.status===6) return 0; throw e; }
  }
  async fileReadAll(size,onProgress,other=false){
    const out=new Uint8Array(size);
    for(let at=0;at<size;at+=this.maxBlock){
      const n=Math.min(this.maxBlock,size-at);
      const r=await this.fileRead(((other?FILE_OTHER:0)|at)>>>0,n);
      out.set(r.bytes,at);
      onProgress?.(at+n,size);
    }
    return out;
  }
  /** Schreibt die Datei neu; der erste Block legt sie an. Das Geraet liest jeden Block zurueck. */
  async fileWrite(bytes,onProgress,other=false){
    for(let at=0;at<bytes.length;at+=this.maxBlock){
      const part=bytes.subarray(at,Math.min(at+this.maxBlock,bytes.length));
      const c=crc32(part);
      this.check(await this.cmd(FN.FILEBEGIN,words(((other?FILE_OTHER:0)|at)>>>0,part.length,c),RE.FILEBEGIN,20000),3,"FILE BEGIN");
      const w=this.check(await this.cmd(FN.WDATA,part,RE.WDATA,20000),4,"FILE DATA");
      if(w[3]!==c) throw new Error("FILE WRITE: das Geraet las andere Bytes von der Karte zurueck");
      onProgress?.(at+part.length,bytes.length);
    }
  }

  /* ---- Code ausfuehren -------------------------------------------------- */
  /** Woerter in den Stub-Puffer, Cache leeren, ausfuehren, Originalbytes zurueck. */
  async exec(wordList){
    const code=new Uint8Array(wordList.length*4);
    new DataView(code.buffer).setUint32(0,0,true);
    wordList.forEach((v,i)=>new DataView(code.buffer).setUint32(i*4,v>>>0,true));
    if(code.length>EXEC_SIZE) throw new Error(`Stub ist ${code.length} Byte, Puffer hat ${EXEC_SIZE}`);
    // Die Cache-Routine der Firmware muss noch die erwarteten Bytes haben.
    const have=await this.read(ICACHE.addr,ICACHE.length);
    if(hex(have)!==ICACHE_BYTES) throw new Error("Die Cache-Routine der Firmware sieht anders aus - abgebrochen");
    const backup=await this.read(EXEC_AT,code.length);
    await this.write(EXEC_AT,code);
    const back=await this.read(EXEC_AT,code.length);
    if(hex(back)!==hex(code)) throw new Error("Stub kam anders zurueck - abgebrochen");
    try{
      this.check(await this.cmd(FN.EXEC,words(ICACHE.addr),RE.EXEC),2,"EXEC Cache");
      this.check(await this.cmd(FN.EXEC,words(EXEC_AT),RE.EXEC),2,"EXEC Stub");
    } finally {
      await this.write(EXEC_AT,backup);
    }
  }
  /** Sucht "REMT" im RAM der Laufzeit und gibt die Postfachadresse. */
  async findMailbox(){
    const len=REMT.to-REMT.from;
    const b=await this.readAll(REMT.from,len);
    const d=new DataView(b.buffer,b.byteOffset);
    for(let at=0;at+8<=b.length;at+=4)
      if(d.getUint32(at,true)===REMT.sign) return d.getUint32(at+4,true);
    return null;
  }
  async press(mailbox,index){ await this.exec(remoteStub(mailbox,remoteWord(REMOTE.KEY,index))); }
  async turn(mailbox,index,delta){ await this.exec(remoteStub(mailbox,remoteWord(REMOTE.ENCODER,index,delta))); }
  /** Wohin die drei Literal-Pools zeigen. */
  async readUpdatePools(){
    const out=[];
    for(const p of UPDATE_POOLS){
      const b=await this.read(p,4);
      out.push(new DataView(b.buffer,b.byteOffset,4).getUint32(0,true)>>>0);
    }
    return out;
  }
  /** Welche Fassung des Patches laeuft: original, gut, kaputt oder unbekannt. */
  async updateStatus(){
    const z=await this.readUpdatePools();
    const alle=v=>z.every(x=>x===v);
    if(alle(UPDATE_KORG))      return {lage:"original",zeiger:z,name:"/SYSTEM.VSB"};
    if(alle(UPDATE_NAME.addr)) return {lage:"gut",zeiger:z,name:await this.readUpdateName()};
    if(alle(UPDATE_NAME_ALT))  return {lage:"kaputt",zeiger:z,name:null};
    return {lage:"unbekannt",zeiger:z,name:null};
  }
  /** Rettung: die drei Pools auf Korgs eigene Zeichenkette zuruecksetzen.
      Danach verhaelt sich SOFTWARE UPDATE wie bei Korg und nimmt System/SYSTEM.VSB. */
  async rescueUpdateName(){
    const w=new Uint8Array(4);
    new DataView(w.buffer).setUint32(0,UPDATE_KORG,true);
    for(const p of UPDATE_POOLS) await this.write(p,w);
    return this.readUpdatePools();
  }
  /** Der Dateiname, den SOFTWARE UPDATE oeffnet, oder null ohne den Patch. */
  async readUpdateName(){
    const b=await this.read(UPDATE_NAME.addr,UPDATE_NAME.size);
    if(b.every(x=>x===0xff)) return null;
    const n=b.indexOf(0);
    return new TextDecoder("latin1").decode(b.subarray(0,n<0?b.length:n));
  }
  async writeUpdateName(name){
    if(!name.startsWith("/")) name="/"+name;
    const roh=new TextEncoder().encode(name);
    if(roh.length>=UPDATE_NAME.size) throw new Error(`Hoechstens ${UPDATE_NAME.size-1} Zeichen`);
    const b=new Uint8Array(UPDATE_NAME.size);
    b.set(roh);
    await this.write(UPDATE_NAME.addr,b);
    return name;
  }
  /* ---- Pattern: Takte 5 bis 8 ---- */
  /** Adresse des ersten Step-Bytes eines Parts. */
  partAddr(part){
    if(part<0||part>=PATTERN.parts) throw new Error(`Part 0 bis ${PATTERN.parts-1}`);
    return PATTERN.addr+PATTERN.kopf+part*PATTERN.part+PATTERN.params;
  }
  /** Die 64 Steps eines Parts, je mit eigenen und freien Bytes. */
  async readSteps(part){
    const b=await this.readAll(this.partAddr(part),PATTERN.steps*PATTERN.step);
    return Array.from({length:PATTERN.steps},(_,n)=>{
      const o=n*PATTERN.step;
      return {on:b[o],gate:b[o+1],velocity:b[o+2],trigger:b[o+3],
              noten:Array.from(b.subarray(o+4,o+8)),
              spaet:{on:b[o+8],gate:b[o+9],velocity:b[o+10],note:b[o+11]}};
    });
  }
  /** Einen Schritt der Takte 5 bis 8 setzen (Step 0 bis 63 = Schritt 64 bis 127). */
  async writeLateStep(part,step,{on=0,gate=0,velocity=0,note=0}={}){
    if(step<0||step>=PATTERN.steps) throw new Error(`Step 0 bis ${PATTERN.steps-1}`);
    const a=this.partAddr(part)+step*PATTERN.step+PATTERN.frei;
    await this.write(a,new Uint8Array([on&0xff,gate&0xff,velocity&0xff,note&0x7f]));
  }
  /** Alle Takte 5 bis 8 eines Parts loeschen. */
  async clearLateBars(part){
    for(let n=0;n<PATTERN.steps;n++) await this.writeLateStep(part,n,{});
  }
  /** Die Laenge des laufenden Patterns, 1 bis 8 Takte. */
  async readLength(){
    const b=await this.read(PATTERN.addr+LAENGE_OFF,1);
    return b[0]+1;
  }
  async writeLength(takte){
    if(takte<1||takte>8) throw new Error("1 bis 8 Takte");
    await this.write(PATTERN.addr+LAENGE_OFF,new Uint8Array([takte-1]));
    return takte;
  }
  async readDisplay(){ return this.readAll(DISPLAY.addr,DISPLAY.size); }
  async writeDisplay(bytes){
    if(bytes.length!==DISPLAY.size) throw new Error(`Ein Bild hat ${DISPLAY.size} Byte`);
    await this.writeAll(DISPLAY.addr,bytes);
  }
}

/* ---- Fernsteuerung ----------------------------------------------------- */
/** Befehlswort: Taste (index) oder Regler `index` um `value` gedreht. */
export function remoteWord(kind,index,value=0){
  if(!Number.isInteger(index)||index<0||index>0xff) throw new RangeError("Index 0 bis 255");
  if(!Number.isInteger(value)||value<-128||value>127) throw new RangeError("Drehen um -128 bis 127");
  return (REMOTE.MARK|(value&0xff)<<16|index<<8|kind)>>>0;
}
/** Zaehler merken, Wort ablegen, bis zu 50 x 10 ms warten, bis die Laufzeit es abgearbeitet hat. */
export function remoteStub(mailbox,word){
  return [
    0xe92d4070, 0xe59f4034, 0xe5945008, 0xe59f0030, 0xe5840000,
    (0xe3a06000|REMOTE.TRIES)>>>0, 0xe3a0000a, 0xe59fc024, 0xe12fff3c,
    0xe5940008, 0xe1500005, 0x1a000001, 0xe2566001, 0x1afffff7,
    0xe3a00001, 0xe8bd8070,
    mailbox>>>0, word>>>0, REMOTE.OS_WAIT,
  ];
}
/** Postfachadresse aus einer geladenen SYSTEM.VSB. */
export function mailboxOf(vsb){
  const from=ramToFile(REMT.from), to=Math.min(ramToFile(REMT.to),vsb.length-8);
  const d=new DataView(vsb.buffer,vsb.byteOffset,vsb.length);
  for(let at=from;at<to;at+=4) if(d.getUint32(at,true)===REMT.sign) return d.getUint32(at+4,true);
  return null;
}

/* ---- Bilder ------------------------------------------------------------ */
/** Displaybytes (Bit 0 oben) -> 128x64 Pixel, 1 = hell. */
export const displayToPixels=b=>{
  const px=new Uint8Array(DISPLAY.w*DISPLAY.h);
  for(let y=0;y<DISPLAY.h;y++) for(let x=0;x<DISPLAY.w;x++)
    px[y*DISPLAY.w+x]=(b[(y>>3)*DISPLAY.w+x]>>(y&7))&1;
  return px;
};
/** Startbildbytes (Bit 7 oben) -> Pixel, 1 = dunkel auf dem Geraet. */
export const splashToPixels=b=>{
  const px=new Uint8Array(SPLASH.w*SPLASH.h);
  for(let y=0;y<SPLASH.h;y++) for(let x=0;x<SPLASH.w;x++)
    px[y*SPLASH.w+x]=(b[(y>>3)*SPLASH.w+x]>>(7-(y&7)))&1;
  return px;
};
export const pixelsToSplash=px=>{
  const b=new Uint8Array(SPLASH.size);
  for(let y=0;y<SPLASH.h;y++) for(let x=0;x<SPLASH.w;x++)
    if(px[y*SPLASH.w+x]) b[(y>>3)*SPLASH.w+x]|=0x80>>(y&7);
  return b;
};

/* ---- Effekt-Presets ---------------------------------------------------- */
/* Record 0x20C Byte. Name 0x01 (16), Steuerzeilen ab 0x12 (10 x 0x1C),
   Bausteine 0x12A/0x174/0x1BE, Parameter ab Baustein+0x0B, Schrittweite 2. */
export const REC=0x20c, NAME=0x01, CTRL=0x12, CTRL_SZ=0x1c;
export const STAGE={ifx1:0x12a,ifx2:0x174,mfx:0x1be};
/* Mit preset-tables liegen die Zeigertabellen hier (128 Plaetze). */
export const PTRS={ifx:0xC017C000,mfx:0xC017C200,count:128};
export const recName=r=>new TextDecoder("latin1").decode(r.subarray(NAME,0x12)).split("\0")[0];
export function setRecName(r,s){
  const b=new TextEncoder().encode(s.slice(0,16));
  r.fill(0,NAME,0x12); r.set(b,NAME);
}
export const recDevice=(r,st)=>r[STAGE[st]];
export const recParam=(r,st,k)=>r[STAGE[st]+0x0b+2*k];
export const setRecParam=(r,st,k,v)=>{r[STAGE[st]+0x0b+2*k]=v&0x7f;};
export function recRows(r){
  const out=[];
  for(let i=0;i<10;i++){
    const o=CTRL+i*CTRL_SZ, s=r.subarray(o,o+CTRL_SZ);
    if(s.some(x=>x)) out.push({row:i,source:s[0],chain:s[1],param:s[2],low:s[4],high:s[6]});
  }
  return out;
}
/** Die Zeiger einer Tabelle aus einer geladenen SYSTEM.VSB. */
export function pointersOf(vsb,table,count=PTRS.count){
  const d=new DataView(vsb.buffer,vsb.byteOffset,vsb.length);
  const at=ramToFile(table);
  return Array.from({length:count},(_,i)=>d.getUint32(at+4*i,true));
}
/** Ein Record aus einer geladenen SYSTEM.VSB, als Sicht auf dieselben Bytes. */
export function recordOf(vsb,pointer){
  const at=ramToFile(pointer);
  if(at<0||at+REC>vsb.length) return null;
  return vsb.subarray(at,at+REC);
}

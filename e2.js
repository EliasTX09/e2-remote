/* Electribe 2 over Web MIDI - Protokollschicht.
   Rahmen: F0 42 3n 00 01 24 <Funktion> <7-bit-gepackte Nutzdaten> F7
   Nutzdaten: 32-Bit-Woerter, Little Endian, Korgs 8-in-7-Packung.
   Belege: hacktribe/scripts/e2_syx_codec.py, kuhlers-gelumpe docs/messungen/2026-10-15-blech-sysex.md */
export const FN = { INFO:0x60, READ:0x61, WBEGIN:0x62, WDATA:0x63, FREAD:0x64, EXEC:0x6f };
export const RE = { INFO:0x68, READ:0x69, WBEGIN:0x6a, WDATA:0x6b, FREAD:0x6c, EXEC:0x70 };
export const STATUS = ["in Ordnung","Pruefsumme stimmt nicht","verweigert",
  "ausserhalb des erlaubten Bereichs","Flash-Funktion meldet keinen Erfolg","Rueckgelesenes weicht ab"];
export const MAX_BLOCK = 32768;

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

export class E2 {
  constructor(){ this.inp=null; this.out=null; this.channel=0; this.id=0x24; this.pending=null; this.log=()=>{}; }
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
  /** Wartet auf die naechste SysEx-Antwort. */
  wait(ms=4000){
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
  /** Eine BLECH-Anfrage, geprueft gegen das erwartete Antwortbyte. */
  async cmd(fn,payload,expect){
    this.send(this.frame(fn,payload));
    const r=await this.wait();
    if(r[6]!==expect) throw new Error(`Antwort 0x${r[6].toString(16)} statt 0x${expect.toString(16)}`);
    return unpack(r.subarray(7,r.length-1));
  }
  async info(){
    const p=await this.cmd(FN.INFO,new Uint8Array(0),RE.INFO);
    const w=readWords(p,6);
    return {status:w[0], version:w[1], flags:w[2], maxBlock:w[3], tableCrc:w[4], maxFlashBlock:w[5],
            kann:{lesen:!!(w[2]&1),schreiben:!!(w[2]&2),crc:!!(w[2]&4),flash:!!(w[2]&8)}};
  }
  async read(addr,len){
    if(len<1||len>MAX_BLOCK) throw new Error(`Laenge 1 bis ${MAX_BLOCK}`);
    const p=await this.cmd(FN.READ,words(addr,len),RE.READ);
    const w=readWords(p,4);
    if(w[0]!==0) throw new Error("READ: "+(STATUS[w[0]]||w[0]));
    const data=p.subarray(16,16+w[2]);
    if(crc32(data)!==w[3]) throw new Error("READ: CRC der Antwort stimmt nicht");
    return data;
  }
  /** Liest beliebig viel in Bloecken. */
  async readAll(addr,len,onProgress){
    const out=new Uint8Array(len);
    for(let o=0;o<len;o+=MAX_BLOCK){
      const n=Math.min(MAX_BLOCK,len-o);
      out.set(await this.read(addr+o,n),o);
      onProgress?.(o+n,len);
    }
    return out;
  }
  async write(addr,data){
    if(data.length<1||data.length>MAX_BLOCK) throw new Error(`Laenge 1 bis ${MAX_BLOCK}`);
    const c=crc32(data);
    let p=await this.cmd(FN.WBEGIN,words(addr,data.length,c),RE.WBEGIN);
    let w=readWords(p,3);
    if(w[0]!==0) throw new Error("WRITE BEGIN: "+(STATUS[w[0]]||w[0]));
    p=await this.cmd(FN.WDATA,data,RE.WDATA);
    w=readWords(p,4);
    if(w[0]!==0) throw new Error("WRITE DATA: "+(STATUS[w[0]]||w[0]));
    if(w[3]!==c) throw new Error("WRITE: das Geraet las andere Bytes zurueck");
    return w;
  }
  async writeAll(addr,data,onProgress){
    for(let o=0;o<data.length;o+=MAX_BLOCK){
      const n=Math.min(MAX_BLOCK,data.length-o);
      await this.write(addr+o,data.subarray(o,o+n));
      onProgress?.(o+n,data.length);
    }
  }
  async flashRead(addr,len){
    const p=await this.cmd(FN.FREAD,words(addr,len),RE.FREAD);
    const w=readWords(p,4);
    if(w[0]!==0) throw new Error("FLASH READ: "+(STATUS[w[0]]||w[0]));
    return p.subarray(16,16+w[2]);
  }
}

/* ---- Effekt-Presets ---------------------------------------------------- */
/* Record 0x20C Byte. Name 0x01 (16), Steuerzeilen ab 0x12 (10 x 0x1C),
   Bausteine 0x12A/0x174/0x1BE, Parameter ab Baustein+0x0B, Schrittweite 2. */
export const REC=0x20c, NAME=0x01, CTRL=0x12, CTRL_SZ=0x1c;
export const STAGE={ifx1:0x12a,ifx2:0x174,mfx:0x1be};
/* Mit BLECHs preset-tables liegen die Zeigertabellen hier (128 Plaetze). */
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

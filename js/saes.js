/* =========================================================
   Simplified AES (S-AES) — full engine + step trace
   16-bit block, 16-bit key, state as 2x2 nibble matrix (column-major):
      n0 n2
      n1 n3
   ========================================================= */
const SAES = (() => {

  const SBOX = [0x9,0x4,0xA,0xB,0xD,0x1,0x8,0x5,0x6,0x2,0x0,0x3,0xC,0xE,0xF,0x7];
  const INV_SBOX = new Array(16);
  SBOX.forEach((v,i) => INV_SBOX[v] = i);

  const RCON1 = 0x80, RCON2 = 0x30; // as bytes (n3n2n1n0 style, 8 bits)

  function hx(n){ return n.toString(16).toUpperCase(); }
  function nibbles(str16){ // '1010110011110000' -> [n0,n1,n2,n3] each 4-bit string
    return CL.chunk(str16, 4);
  }
  function toByte(nibHi, nibLo){ return (parseInt(nibHi,2) << 4) | parseInt(nibLo,2); }
  function byteToNibs(b){ return [CL.dec2bin((b>>4)&0xF,4), CL.dec2bin(b&0xF,4)]; }

  function subNibByte(byte){
    const hi = (byte>>4)&0xF, lo = byte&0xF;
    return (SBOX[hi]<<4) | SBOX[lo];
  }
  function rotNibByte(byte){
    const hi = (byte>>4)&0xF, lo = byte&0xF;
    return (lo<<4) | hi;
  }

  function keyExpansion(key16, steps){
    const nb = nibbles(key16); // 4 nibbles
    let w0 = toByte(nb[0], nb[1]);
    let w1 = toByte(nb[2], nb[3]);

    steps.push({type:'sub', title:'Kunci awal → w0, w1', rows:[
      {label:'Key (16-bit)', value:key16, group:'violet'},
      {label:'w0 (byte)', value: CL.dec2bin(w0,8), meta:hx(w0)},
      {label:'w1 (byte)', value: CL.dec2bin(w1,8), meta:hx(w1)},
    ]});

    function g(w, rcon, label){
      const rot = rotNibByte(w);
      const sub = subNibByte(rot);
      const out = sub ^ rcon;
      steps.push({type:'sub', title:`g(${label}) = SubNib(RotNib(${label})) XOR RCON`, rows:[
        {label:`${label}`, value:CL.dec2bin(w,8), meta:hx(w)},
        {label:'RotNib', value:CL.dec2bin(rot,8), meta:hx(rot), group:'cyan'},
        {label:'SubNib', value:CL.dec2bin(sub,8), meta:hx(sub), group:'amber'},
        {label:'RCON', value:CL.dec2bin(rcon,8), meta:hx(rcon), group:'red'},
        {label:`g(${label})`, value:CL.dec2bin(out,8), meta:hx(out), group:'violet'},
      ]});
      return out;
    }

    const g1 = g(w1, RCON1, 'w1');
    const w2 = w0 ^ g1;
    const w3 = w2 ^ w1;
    steps.push({type:'sub', title:'w2, w3 (Round Key K1 = w2||w3)', rows:[
      {label:'w2 = w0 XOR g(w1)', value:CL.dec2bin(w2,8), meta:hx(w2), group:'amber'},
      {label:'w3 = w2 XOR w1', value:CL.dec2bin(w3,8), meta:hx(w3), group:'amber'},
    ]});

    const g3 = g(w3, RCON2, 'w3');
    const w4 = w2 ^ g3;
    const w5 = w4 ^ w3;
    steps.push({type:'sub', title:'w4, w5 (Round Key K2 = w4||w5)', rows:[
      {label:'w4 = w2 XOR g(w3)', value:CL.dec2bin(w4,8), meta:hx(w4), group:'amber'},
      {label:'w5 = w4 XOR w3', value:CL.dec2bin(w5,8), meta:hx(w5), group:'amber'},
    ]});

    const K0 = w0.toString(2).padStart(8,'0') + w1.toString(2).padStart(8,'0');
    const K1 = w2.toString(2).padStart(8,'0') + w3.toString(2).padStart(8,'0');
    const K2 = w4.toString(2).padStart(8,'0') + w5.toString(2).padStart(8,'0');
    steps.push({type:'sub', title:'Round Keys terbentuk', rows:[
      {label:'K0', value:K0, meta:CL.binToHex(K0), group:'violet'},
      {label:'K1', value:K1, meta:CL.binToHex(K1), group:'violet'},
      {label:'K2', value:K2, meta:CL.binToHex(K2), group:'violet'},
    ]});
    return {K0, K1, K2};
  }

  // state helpers: array of 4 nibble decimal values [s0,s1,s2,s3] laid out as
  // s0 s2
  // s1 s3
  function stateFromBits(bits16){ return nibbles(bits16).map(n => parseInt(n,2)); }
  function stateToBits(s){ return s.map(n => CL.dec2bin(n,4)).join(''); }

  function matrixBlock(label, s){
    return {type:'matrix', label, cols:2, values:[
      [hx(s[0]), hx(s[2])],
      [hx(s[1]), hx(s[3])],
    ]};
  }

  function addRoundKey(s, kBits){
    const k = stateFromBits(kBits);
    return s.map((v,i) => v ^ k[i]);
  }

  function subNibState(s, inv){
    const table = inv ? INV_SBOX : SBOX;
    return s.map(v => table[v]);
  }

  function shiftRows(s){
    // s0 s2 / s1 s3  -> shift row1 (s1,s3) left by 1 -> (s3,s1)
    return [s[0], s[3], s[2], s[1]];
  }

  function gmul4(a,b){ return CL.gfMul(a,b,0x03,4); } // x^4+x+1, leading term stripped

  function mixColumns(s, inv){
    // columns: (s0,s1) and (s2,s3)
    const M = inv ? [[9,2],[2,9]] : [[1,4],[4,1]];
    function mixCol(c0,c1){
      return [
        gmul4(M[0][0],c0) ^ gmul4(M[0][1],c1),
        gmul4(M[1][0],c0) ^ gmul4(M[1][1],c1),
      ];
    }
    const [a0,a1] = mixCol(s[0], s[1]);
    const [b0,b1] = mixCol(s[2], s[3]);
    return [a0, a1, b0, b1];
  }

  function run(input16, key16, mode){
    const steps = [];
    steps.push({title:'1. Input', body:[
      {type:'bits', label: mode==='enc' ? 'Plaintext (16-bit)' : 'Ciphertext (16-bit)', value:input16, group:'amber', chunks: nibbles(input16)},
      {type:'bits', label:'Key (16-bit)', value:key16, group:'violet', chunks: nibbles(key16)},
      {type:'text', text:`Mode: <b>${mode==='enc' ? 'Enkripsi':'Dekripsi'}</b>`},
    ]});

    const keSteps = [];
    const {K0,K1,K2} = keyExpansion(key16, keSteps);
    steps.push({title:'2. Key Expansion (w0–w5 → K0, K1, K2)', body: keSteps});

    let s = stateFromBits(input16);
    steps.push({title:'3. Initial Round — AddRoundKey(K0)', body:[
      matrixBlock('State awal', s),
      matrixBlock('K0', stateFromBits(K0)),
      (() => { s = addRoundKey(s, K0); return matrixBlock('State XOR K0', s); })(),
    ]});

    if (mode === 'enc') {
      // Round 1
      const r1 = [];
      let sn = subNibState(s,false); r1.push(matrixBlock('Setelah SubNib', sn));
      let sr = shiftRows(sn);        r1.push(matrixBlock('Setelah ShiftRows', sr));
      let mc = mixColumns(sr,false); r1.push(matrixBlock('Setelah MixColumns', mc));
      s = addRoundKey(mc, K1);       r1.push(matrixBlock('AddRoundKey(K1) → State', s));
      steps.push({title:'4. Ronde 1', round:true, body:r1});

      // Round 2
      const r2 = [];
      sn = subNibState(s,false); r2.push(matrixBlock('Setelah SubNib', sn));
      sr = shiftRows(sn);        r2.push(matrixBlock('Setelah ShiftRows', sr));
      s = addRoundKey(sr, K2);   r2.push(matrixBlock('AddRoundKey(K2) → State (Ciphertext)', s));
      steps.push({title:'5. Ronde 2 (tanpa MixColumns)', round:true, body:r2});

    } else {
      // decrypt: start from AddRoundKey(K2) as the "initial round" above actually used K0 for symmetry of engine;
      // but for correct S-AES decryption we must start with K2. Recompute properly below.
      s = addRoundKey(stateFromBits(input16), K2);
      steps[2] = {title:'3. Initial Round — AddRoundKey(K2)', body:[
        matrixBlock('State awal (ciphertext)', stateFromBits(input16)),
        matrixBlock('K2', stateFromBits(K2)),
        matrixBlock('State XOR K2', s),
      ]};

      const r1 = [];
      let sr = shiftRows(s);            r1.push(matrixBlock('InvShiftRows', sr));
      let sn = subNibState(sr,true);    r1.push(matrixBlock('InvSubNib', sn));
      s = addRoundKey(sn, K1);          r1.push(matrixBlock('AddRoundKey(K1)', s));
      let mc = mixColumns(s,true);      r1.push(matrixBlock('InvMixColumns', mc));
      s = mc;
      steps.push({title:'4. Ronde 1 (invers)', round:true, body:r1});

      const r2 = [];
      sr = shiftRows(s);                r2.push(matrixBlock('InvShiftRows', sr));
      sn = subNibState(sr,true);        r2.push(matrixBlock('InvSubNib', sn));
      s = addRoundKey(sn, K0);          r2.push(matrixBlock('AddRoundKey(K0) → State (Plaintext)', s));
      steps.push({title:'5. Ronde 2 (invers, tanpa MixColumns)', round:true, body:r2});
    }

    const output = stateToBits(s);
    steps.push({title:'6. Hasil Akhir', body:[
      matrixBlock('State akhir', s),
      {type:'bits', label: mode==='enc' ? 'Ciphertext (16-bit)' : 'Plaintext (16-bit)', value:output, group:'amber', chunks: nibbles(output)},
    ]});

    return { output, K0, K1, K2, steps };
  }

  return { run, SBOX, INV_SBOX };
})();

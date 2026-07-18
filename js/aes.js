/* =========================================================
   AES-128 — full engine + step trace (10 rounds)
   State is a 4x4 byte matrix filled column-major from the 16 input bytes,
   exactly as in FIPS-197.
   ========================================================= */
const AES = (() => {

  const SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
  ];
  const INV_SBOX = new Array(256);
  SBOX.forEach((v,i) => INV_SBOX[v] = i);

  const RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36];

  function hx2(n){ return n.toString(16).toUpperCase().padStart(2,'0'); }
  function hexPairs(hex32){ const out=[]; for (let i=0;i<hex32.length;i+=2) out.push(hex32.slice(i,i+2).toUpperCase()); return out; }

  /** bytes[16] -> 4x4 state, column-major: state[row][col] = bytes[col*4+row] */
  function bytesToState(bytes){
    const st = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]];
    for (let c=0;c<4;c++) for (let r=0;r<4;r++) st[r][c] = bytes[c*4+r];
    return st;
  }
  function stateToBytes(st){
    const out = [];
    for (let c=0;c<4;c++) for (let r=0;r<4;r++) out.push(st[r][c]);
    return out;
  }
  function cloneState(st){ return st.map(row => row.slice()); }
  function matrixBlock(label, st){
    return {type:'matrix', label, cols:4, values: st.map(row => row.map(hx2))};
  }

  function subBytes(st, inv){
    const table = inv ? INV_SBOX : SBOX;
    return st.map(row => row.map(v => table[v]));
  }
  function shiftRows(st, inv){
    const out = cloneState(st);
    for (let r=1;r<4;r++){
      const row = st[r];
      const shifted = inv ? [ row[(4-r)%4], row[(5-r)%4], row[(6-r)%4], row[(7-r)%4] ]
                           : [ row[(r)%4], row[(r+1)%4], row[(r+2)%4], row[(r+3)%4] ];
      out[r] = shifted;
    }
    return out;
  }
  function gmul8(a,b){ return CL.gfMul(a,b,0x1B,8); }

  function mixColumns(st, inv){
    const M = inv ? [[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]]
                  : [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]];
    const out = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]];
    for (let c=0;c<4;c++){
      const col = [st[0][c], st[1][c], st[2][c], st[3][c]];
      for (let r=0;r<4;r++){
        out[r][c] = gmul8(M[r][0],col[0]) ^ gmul8(M[r][1],col[1]) ^ gmul8(M[r][2],col[2]) ^ gmul8(M[r][3],col[3]);
      }
    }
    return out;
  }
  function addRoundKey(st, roundKeyBytes){
    const rk = bytesToState(roundKeyBytes);
    return st.map((row,r) => row.map((v,c) => v ^ rk[r][c]));
  }

  function keyExpansion(keyBytes, steps){
    const Nk = 4, Nr = 10, Nb = 4;
    const W = [];
    for (let i=0;i<Nk;i++) W.push([keyBytes[4*i],keyBytes[4*i+1],keyBytes[4*i+2],keyBytes[4*i+3]]);
    steps.push({type:'sub', title:'Kata kunci awal W0–W3', rows: W.map((w,i) => ({label:`W${i}`, value: w.map(hx2).join(' ')}))});

    for (let i=Nk;i<Nb*(Nr+1);i++){
      let temp = W[i-1].slice();
      if (i % Nk === 0){
        const rotated = [temp[1],temp[2],temp[3],temp[0]];
        const subbed = rotated.map(b => SBOX[b]);
        const rc = RCON[i/Nk - 1];
        const rconWord = [rc,0,0,0];
        const afterRcon = subbed.map((b,idx) => b ^ rconWord[idx]);
        steps.push({type:'sub', title:`W${i}: RotWord → SubWord → XOR Rcon[${i/Nk}]`, rows:[
          {label:`W${i-1}`, value: temp.map(hx2).join(' ')},
          {label:'RotWord', value: rotated.map(hx2).join(' '), group:'cyan'},
          {label:'SubWord', value: subbed.map(hx2).join(' '), group:'amber'},
          {label:`Rcon[${i/Nk}]`, value: rconWord.map(hx2).join(' '), group:'red'},
          {label:'g(W) hasil', value: afterRcon.map(hx2).join(' '), group:'violet'},
        ]});
        temp = afterRcon;
      }
      const w = W[i-Nk].map((b,idx) => b ^ temp[idx]);
      W.push(w);
      if (i % Nk === 0){
        steps.push({type:'sub', title:`W${i} = W${i-Nk} XOR g(W${i-1})`, rows:[
          {label:`W${i}`, value: w.map(hx2).join(' '), group:'amber'},
        ]});
      }
    }

    const roundKeys = [];
    for (let rnd=0; rnd<=Nr; rnd++){
      const bytes = [].concat(W[rnd*4], W[rnd*4+1], W[rnd*4+2], W[rnd*4+3]);
      roundKeys.push(bytes);
    }
    steps.push({type:'sub', title:'11 Round Key terbentuk (AES-128)', rows: roundKeys.map((rk,i) => ({label:`RoundKey ${i}`, value: rk.map(hx2).join(' ')}))});
    return roundKeys;
  }

  function run(input128hex, key128hex, mode){
    const steps = [];
    const inBytes = hexPairs(input128hex).map(h => parseInt(h,16));
    const keyBytes = hexPairs(key128hex).map(h => parseInt(h,16));

    steps.push({title:'1. Input', body:[
      {type:'bits', label: mode==='enc' ? 'Plaintext (128-bit hex)' : 'Ciphertext (128-bit hex)', value:input128hex.toUpperCase(), group:'amber', chunks: hexPairs(input128hex)},
      {type:'bits', label:'Key (128-bit hex)', value:key128hex.toUpperCase(), group:'violet', chunks: hexPairs(key128hex)},
      {type:'text', text:`Mode: <b>${mode==='enc' ? 'Enkripsi':'Dekripsi'}</b>. Byte-byte disusun sebagai matriks state 4×4 secara column-major.`},
    ]});

    const keSteps = [];
    const roundKeys = keyExpansion(keyBytes, keSteps);
    steps.push({title:'2. Key Expansion (RotWord, SubWord, XOR Rcon)', body: keSteps});

    let st = bytesToState(inBytes);

    if (mode === 'enc') {
      steps.push({title:'3. Initial Round — AddRoundKey(RoundKey 0)', body:[
        matrixBlock('State awal', st),
        matrixBlock('RoundKey 0', bytesToState(roundKeys[0])),
        (() => { st = addRoundKey(st, roundKeys[0]); return matrixBlock('State setelah AddRoundKey', st); })(),
      ]});

      for (let rnd=1; rnd<=9; rnd++){
        const body = [];
        st = subBytes(st,false);      body.push(matrixBlock('SubBytes', st));
        st = shiftRows(st,false);     body.push(matrixBlock('ShiftRows', st));
        st = mixColumns(st,false);    body.push(matrixBlock('MixColumns', st));
        st = addRoundKey(st, roundKeys[rnd]); body.push(matrixBlock(`AddRoundKey (RoundKey ${rnd})`, st));
        steps.push({title:`Ronde ${rnd}`, round:true, body});
      }

      const body10 = [];
      st = subBytes(st,false);   body10.push(matrixBlock('SubBytes', st));
      st = shiftRows(st,false);  body10.push(matrixBlock('ShiftRows', st));
      st = addRoundKey(st, roundKeys[10]); body10.push(matrixBlock('AddRoundKey (RoundKey 10) — tanpa MixColumns', st));
      steps.push({title:'Ronde 10 (terakhir)', round:true, body:body10});

    } else {
      steps.push({title:'3. Initial Round — AddRoundKey(RoundKey 10)', body:[
        matrixBlock('State awal (ciphertext)', st),
        matrixBlock('RoundKey 10', bytesToState(roundKeys[10])),
        (() => { st = addRoundKey(st, roundKeys[10]); return matrixBlock('State setelah AddRoundKey', st); })(),
      ]});

      for (let rnd=9; rnd>=1; rnd--){
        const body = [];
        st = shiftRows(st,true);   body.push(matrixBlock('InvShiftRows', st));
        st = subBytes(st,true);    body.push(matrixBlock('InvSubBytes', st));
        st = addRoundKey(st, roundKeys[rnd]); body.push(matrixBlock(`AddRoundKey (RoundKey ${rnd})`, st));
        st = mixColumns(st,true);  body.push(matrixBlock('InvMixColumns', st));
        steps.push({title:`Ronde ${10-rnd} (invers, pakai RoundKey ${rnd})`, round:true, body});
      }

      const bodyLast = [];
      st = shiftRows(st,true);  bodyLast.push(matrixBlock('InvShiftRows', st));
      st = subBytes(st,true);   bodyLast.push(matrixBlock('InvSubBytes', st));
      st = addRoundKey(st, roundKeys[0]); bodyLast.push(matrixBlock('AddRoundKey (RoundKey 0) — tanpa InvMixColumns', st));
      steps.push({title:'Ronde 10 (invers, terakhir)', round:true, body:bodyLast});
    }

    const outBytes = stateToBytes(st);
    const outHex = outBytes.map(hx2).join('');
    steps.push({title:'4. Hasil Akhir', body:[
      matrixBlock('State akhir', st),
      {type:'bits', label: mode==='enc' ? 'Ciphertext (128-bit hex)' : 'Plaintext (128-bit hex)', value:outHex, group:'amber', chunks: hexPairs(outHex)},
    ]});

    return { output: outHex, roundKeys, steps };
  }

  return { run, SBOX, INV_SBOX, RCON };
})();

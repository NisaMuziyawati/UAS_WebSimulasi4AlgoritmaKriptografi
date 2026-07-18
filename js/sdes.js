/* =========================================================
   Simplified DES (S-DES) — full engine + step trace
   Reference tables follow the classic Schaefer/Stallings scheme.
   ========================================================= */
const SDES = (() => {

  const P10  = [3,5,2,7,4,10,1,9,8,6];
  const P8   = [6,3,7,4,8,5,10,9];
  const IP   = [2,6,3,1,4,8,5,7];
  const IP1  = [4,1,3,5,7,2,8,6];
  const EP   = [4,1,2,3,2,3,4,1];
  const P4   = [2,4,3,1];

  const S0 = [
    [1,0,3,2],
    [3,2,1,0],
    [0,2,1,3],
    [3,1,3,2],
  ];
  const S1 = [
    [0,1,2,3],
    [2,0,1,3],
    [3,0,1,0],
    [2,1,0,3],
  ];

  function sboxLookup(sbox, fourBits, sboxSteps, label){
    const r = parseInt(fourBits[0] + fourBits[3], 2);
    const c = parseInt(fourBits[1] + fourBits[2], 2);
    const val = sbox[r][c];
    const out = CL.dec2bin(val, 2);
    sboxSteps.push({
      type: 'sbox',
      title: `${label} — input ${fourBits} → baris ${r} (bit1,bit4), kolom ${c} (bit2,bit3)`,
      data: sbox,
      rows: [0,1,2,3], cols: [0,1,2,3],
      hitRow: r, hitCol: c,
      desc: `Hasil ${label}(${fourBits}) = ${val} = ${out}₂`
    });
    return out;
  }

  function keySchedule(key10, steps){
    const p10 = CL.permute(key10, P10);
    let L = p10.slice(0,5), R = p10.slice(5);
    steps.push({type:'sub', title:'Permutasi P10', rows:[
      {label:'Kunci awal (10-bit)', value:key10},
      {label:'Setelah P10', value:p10, group:'amber'},
      {label:'L0 (5-bit kiri)', value:L, group:'cyan'},
      {label:'R0 (5-bit kanan)', value:R, group:'cyan'},
    ]});

    const L1 = CL.leftShift(L,1), R1 = CL.leftShift(R,1);
    const k1pre = L1+R1;
    const K1 = CL.permute(k1pre, P8);
    steps.push({type:'sub', title:'Left Shift 1 (LS-1) → K1', rows:[
      {label:'L1 = LS-1(L0)', value:L1, group:'amber'},
      {label:'R1 = LS-1(R0)', value:R1, group:'amber'},
      {label:'Gabungan L1R1', value:k1pre},
      {label:'K1 = P8(L1R1)', value:K1, group:'violet'},
    ]});

    const L2 = CL.leftShift(L1,2), R2 = CL.leftShift(R1,2);
    const k2pre = L2+R2;
    const K2 = CL.permute(k2pre, P8);
    steps.push({type:'sub', title:'Left Shift 2 (LS-2) → K2', rows:[
      {label:'L2 = LS-2(L1)', value:L2, group:'amber'},
      {label:'R2 = LS-2(R1)', value:R2, group:'amber'},
      {label:'Gabungan L2R2', value:k2pre},
      {label:'K2 = P8(L2R2)', value:K2, group:'violet'},
    ]});

    return {K1, K2};
  }

  function fk(bits8, subkey, roundLabel, out){
    const L = bits8.slice(0,4), R = bits8.slice(4);
    const ep = CL.permute(R, EP);
    const xored = CL.xor(ep, subkey);
    const left4 = xored.slice(0,4), right4 = xored.slice(4);

    const sboxSteps = [];
    const s0out = sboxLookup(S0, left4, sboxSteps, 'S0');
    const s1out = sboxLookup(S1, right4, sboxSteps, 'S1');
    const sCombined = s0out + s1out;
    const p4 = CL.permute(sCombined, P4);
    const newL = CL.xor(p4, L);

    out.push({type:'sub', title:`${roundLabel} — Expansion/Permutation (E/P)`, desc:'8-bit kanan diperluas menjadi 8-bit melalui tabel E/P.', rows:[
      {label:'L (4-bit kiri)', value:L, group:'cyan'},
      {label:'R (4-bit kanan)', value:R, group:'cyan'},
      {label:'E/P(R)', value:ep, group:'amber'},
    ]});
    out.push({type:'sub', title:`${roundLabel} — XOR dengan subkey (${subkey})`, rows:[
      {label:'E/P(R)', value:ep},
      {label:`Subkey`, value:subkey, group:'red'},
      {label:'Hasil XOR', value:xored, group:'amber'},
      {label:'→ ke S0 (4 bit kiri)', value:left4},
      {label:'→ ke S1 (4 bit kanan)', value:right4},
    ]});
    out.push(...sboxSteps);
    out.push({type:'sub', title:`${roundLabel} — Gabungan S-Box & Permutasi P4`, rows:[
      {label:'Gabungan S0(out)+S1(out)', value:sCombined, group:'amber'},
      {label:'P4(gabungan)', value:p4, group:'violet'},
    ]});
    out.push({type:'sub', title:`${roundLabel} — XOR dengan L, hasil`, rows:[
      {label:'P4', value:p4},
      {label:'L sebelumnya', value:L, group:'cyan'},
      {label:`L' = P4 XOR L`, value:newL, group:'amber'},
      {label:'R (tidak berubah)', value:R, group:'cyan'},
    ]});
    return {newL, R};
  }

  function run(input8, key10, mode){
    const steps = [];

    steps.push({title:'1. Input', body:[
      {type:'bits', label: mode==='enc' ? 'Plaintext (8-bit)' : 'Ciphertext (8-bit)', value:input8, group:'amber', chunks:[input8]},
      {type:'bits', label:'Kunci (10-bit)', value:key10, group:'violet', chunks:[key10]},
      {type:'text', text:`Mode: <b>${mode==='enc' ? 'Enkripsi':'Dekripsi'}</b>`},
    ]});

    const ksSteps = [];
    const {K1, K2} = keySchedule(key10, ksSteps);
    steps.push({title:'2. Key Generation (K1 & K2)', body: ksSteps});

    const ip = CL.permute(input8, IP);
    steps.push({title:'3. Initial Permutation (IP)', body:[
      {type:'bits', label:'Sebelum IP', value:input8, chunks:[input8]},
      {type:'bits', label:'Setelah IP', value:ip, group:'amber', chunks:[ip]},
    ]});

    const kOrder = mode === 'enc' ? [K1, K2] : [K2, K1];
    const kLabelOrder = mode === 'enc' ? ['K1','K2'] : ['K2','K1'];

    // Round function 1
    const r1body = [];
    const r1 = fk(ip, kOrder[0], `Round 1 (pakai ${kLabelOrder[0]})`, r1body);
    const afterR1 = r1.newL + r1.R;
    r1body.push({type:'bits', label:`Hasil setelah Round 1 (L'+R)`, value:afterR1, group:'cyan', chunks:[r1.newL, r1.R]});
    const swapped = r1.R + r1.newL;
    r1body.push({type:'bits', label:'Setelah SWAP (SW): R + L\'', value:swapped, group:'violet', chunks:[r1.R, r1.newL]});
    steps.push({title:'4. Round Function 1 + Swap', round:true, body:r1body});

    // Round function 2
    const r2body = [];
    const r2 = fk(swapped, kOrder[1], `Round 2 (pakai ${kLabelOrder[1]})`, r2body);
    const preIP1 = r2.newL + r2.R;
    r2body.push({type:'bits', label:`Hasil akhir Round 2 (tanpa swap): L'+R`, value:preIP1, group:'cyan', chunks:[r2.newL, r2.R]});
    steps.push({title:'5. Round Function 2', round:true, body:r2body});

    const output = CL.permute(preIP1, IP1);
    steps.push({title:'6. Final Permutation (IP⁻¹)', body:[
      {type:'bits', label:'Sebelum IP⁻¹', value:preIP1, chunks:[preIP1]},
      {type:'bits', label: mode==='enc' ? 'Ciphertext (hasil akhir)' : 'Plaintext (hasil akhir)', value:output, group:'amber', chunks:[output]},
    ]});

    return { output, K1, K2, steps };
  }

  return { run, P10, P8, IP, IP1, EP, P4, S0, S1 };
})();

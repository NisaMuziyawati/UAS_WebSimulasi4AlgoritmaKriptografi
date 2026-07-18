/* =========================================================
   DES (64-bit) — full engine + step trace (16 rounds, 8 S-boxes)
   ========================================================= */
const DES = (() => {

  const IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
              57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7];
  const IP1 = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
               36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25];
  const E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
             16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1];
  const P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25];
  const PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,
               63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4];
  const PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,
               41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32];
  const SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];

  const SBOXES = [
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
     [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
     [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
     [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
     [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
     [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
     [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
     [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
     [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]],
  ];

  function keySchedule(key64, steps){
    const pc1 = CL.permute(key64, PC1);
    let C = pc1.slice(0,28), D = pc1.slice(28);
    steps.push({type:'sub', title:'Permuted Choice 1 (PC-1)', desc:'64-bit key (termasuk 8 parity bit) direduksi menjadi 56-bit, lalu dibagi C0/D0.', rows:[
      {label:'Key (64-bit)', value:key64, chunks:CL.chunk(key64,8)},
      {label:'Setelah PC-1 (56-bit)', value:pc1, group:'amber', chunks:CL.chunk(pc1,7)},
      {label:'C0', value:C, group:'cyan'},
      {label:'D0', value:D, group:'cyan'},
    ]});

    const subkeys = [];
    for (let i = 0; i < 16; i++){
      C = CL.leftShift(C, SHIFTS[i]);
      D = CL.leftShift(D, SHIFTS[i]);
      const K = CL.permute(C + D, PC2);
      subkeys.push(K);
      steps.push({type:'sub', title:`Ronde ${i+1}: Left Shift ${SHIFTS[i]} → K${i+1}`, rows:[
        {label:`C${i+1}`, value:C, group:'cyan'},
        {label:`D${i+1}`, value:D, group:'cyan'},
        {label:`K${i+1} = PC-2(C${i+1}D${i+1})`, value:K, group:'violet', chunks:CL.chunk(K,6)},
      ]});
    }
    return subkeys;
  }

  function feistel(R32, K48, roundNum, out){
    const ep = CL.permute(R32, E);
    const xored = CL.xor(ep, K48);
    const chunks6 = CL.chunk(xored, 6);
    out.push({type:'sub', title:`Ronde ${roundNum} — Expansion Permutation (E): 32→48 bit`, rows:[
      {label:'R (32-bit)', value:R32, group:'cyan', chunks:CL.chunk(R32,4)},
      {label:'E(R) (48-bit)', value:ep, group:'amber', chunks:CL.chunk(ep,6)},
    ]});
    out.push({type:'sub', title:`Ronde ${roundNum} — XOR dengan subkey K${roundNum}`, rows:[
      {label:'E(R)', value:ep, chunks:CL.chunk(ep,6)},
      {label:`K${roundNum}`, value:K48, group:'red', chunks:CL.chunk(K48,6)},
      {label:'Hasil XOR (48-bit, 8×6-bit)', value:xored, group:'amber', chunks:chunks6},
    ]});

    let sOut = '';
    const sboxBlocks = [];
    chunks6.forEach((c6, idx) => {
      const row = parseInt(c6[0] + c6[5], 2);
      const col = parseInt(c6.slice(1,5), 2);
      const val = SBOXES[idx][row][col];
      const val4 = CL.dec2bin(val, 4);
      sOut += val4;
      sboxBlocks.push({
        type:'sbox',
        title:`S${idx+1}: input ${c6} → baris ${row} (bit1,bit6), kolom ${col} (bit2-5)`,
        data: SBOXES[idx], rows:[0,1,2,3], cols:[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
        hitRow: row, hitCol: col,
        desc: `S${idx+1}(${c6}) = ${val} = ${val4}₂`
      });
    });
    out.push({type:'sub', title:`Ronde ${roundNum} — Substitusi 8 S-Box (48→32 bit)`});
    out.push(...sboxBlocks);

    const pPerm = CL.permute(sOut, P);
    out.push({type:'sub', title:`Ronde ${roundNum} — Gabungan S-Box & Permutasi P`, rows:[
      {label:'Gabungan output 8 S-Box (32-bit)', value:sOut, group:'amber', chunks:CL.chunk(sOut,4)},
      {label:'P(gabungan)', value:pPerm, group:'violet', chunks:CL.chunk(pPerm,4)},
    ]});
    return pPerm;
  }

  function run(input64, key64, mode){
    const steps = [];
    steps.push({title:'1. Diketahui (Input)', body:[
      {type:'bits', label: mode==='enc' ? 'Plaintext (64-bit)' : 'Ciphertext (64-bit)', value:input64, group:'amber', chunks:CL.chunk(input64,8)},
      {type:'bits', label:'Key (64-bit)', value:key64, group:'violet', chunks:CL.chunk(key64,8)},
      {type:'text', text:`Mode: <b>${mode==='enc' ? 'Enkripsi':'Dekripsi'}</b>`},
    ]});

    const ksSteps = [];
    const subkeys = keySchedule(key64, ksSteps);
    steps.push({title:'2. Generate Keys (PC-1, Shift, PC-2 → K1..K16)', body: ksSteps});

    const ip = CL.permute(input64, IP);
    let L = ip.slice(0,32), R = ip.slice(32);
    steps.push({title:'3. Initial Permutation (IP)', body:[
      {type:'bits', label:'Sebelum IP', value:input64, chunks:CL.chunk(input64,8)},
      {type:'bits', label:'Setelah IP', value:ip, group:'amber', chunks:CL.chunk(ip,8)},
      {type:'bits', label:'L0', value:L, group:'cyan', chunks:CL.chunk(L,4)},
      {type:'bits', label:'R0', value:R, group:'cyan', chunks:CL.chunk(R,4)},
    ]});

    const orderedKeys = mode === 'enc' ? subkeys : [...subkeys].reverse();
    const keyLabelIdx = mode === 'enc' ? (i => i+1) : (i => 16-i);

    for (let i = 0; i < 16; i++){
      const body = [];
      const roundLabel = keyLabelIdx(i);
      const fResult = feistel(R, orderedKeys[i], roundLabel, body);
      const newL = R;
      const newR = CL.xor(L, fResult);
      body.push({type:'sub', title:`Ronde ${roundLabel} — XOR dengan L sebelumnya, lalu Swap`, rows:[
        {label:'f(R, K)', value:fResult, chunks:CL.chunk(fResult,4)},
        {label:'L sebelumnya', value:L, group:'cyan', chunks:CL.chunk(L,4)},
        {label:'R baru = f(R,K) XOR L', value:newR, group:'amber', chunks:CL.chunk(newR,4)},
        {label:'L baru = R sebelumnya', value:newL, group:'cyan', chunks:CL.chunk(newL,4)},
      ]});
      L = newL; R = newR;
      body.push({type:'bits', label: `L${roundLabel} dan R${roundLabel} (hasil ronde ini)`, value:L+R, group:'violet', chunks:[L,R]});
      steps.push({title:`Ronde ${roundLabel}`, round:true, body});
    }

    // Standard DES: after 16 rounds the pre-output block is R16‖L16 (final swap of the
    // Feistel network is skipped on round 16), then IP⁻¹ is applied.
    const finalPre = R + L;
    const output = CL.permute(finalPre, IP1);

    steps.push({title:'4. Final Permutation', body:[
      {type:'text', text:'Gabungan L16 dan R16 dari ronde terakhir digabung sebagai R16‖L16 (swap akhir Feistel dilewati pada ronde ke-16), menjadi pre-output, lalu diproses Inverse Initial Permutation (IP⁻¹).'},
      {type:'bits', label:'Pre-output R16L16', value:finalPre, chunks:CL.chunk(finalPre,8)},
      {type:'bits', label: mode==='enc' ? 'Ciphertext (64-bit)' : 'Plaintext (64-bit)', value:output, group:'amber', chunks:CL.chunk(output,8)},
    ]});

    return { output, subkeys, steps };
  }

  return { run, IP, IP1, E, P, PC1, PC2, SHIFTS, SBOXES };
})();

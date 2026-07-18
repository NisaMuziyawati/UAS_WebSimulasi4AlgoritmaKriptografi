/* =========================================================
   CRYPTOLAB — shared helpers
   ========================================================= */

/* ---------- bit / hex utilities ---------- */
const CL = {

  isBin(str){ return /^[01]+$/.test(str); },
  isHex(str){ return /^[0-9a-fA-F]+$/.test(str); },

  hexToBin(hex, bitLen){
    let bin = '';
    for (const ch of hex.trim()) bin += parseInt(ch, 16).toString(2).padStart(4, '0');
    if (bitLen) bin = bin.padStart(bitLen, '0');
    return bin;
  },
  binToHex(bin){
    let padded = bin;
    while (padded.length % 4 !== 0) padded = '0' + padded;
    let hex = '';
    for (let i = 0; i < padded.length; i += 4) hex += parseInt(padded.slice(i, i + 4), 2).toString(16);
    return hex.toUpperCase();
  },

  /** Normalize a user text field to a pure bit string of a given length, accepting bin or hex. */
  toBits(str, bitLen){
    const s = str.trim().replace(/\s+/g, '');
    if (this.isBin(s) && s.length === bitLen) return s;
    if (this.isHex(s)) {
      const b = this.hexToBin(s, bitLen);
      if (b.length === bitLen) return b;
    }
    return null;
  },

  /** classic crypto textbook 1-indexed permutation table */
  permute(bits, table){
    return table.map(pos => bits[pos - 1]).join('');
  },

  xor(a, b){
    let out = '';
    for (let i = 0; i < a.length; i++) out += (a[i] === b[i]) ? '0' : '1';
    return out;
  },

  leftShift(bits, n){
    n = n % bits.length;
    return bits.slice(n) + bits.slice(0, n);
  },

  bin2dec(bits){ return parseInt(bits, 2); },
  dec2bin(n, len){ return n.toString(2).padStart(len, '0'); },

  chunk(str, size){
    const out = [];
    for (let i = 0; i < str.length; i += size) out.push(str.slice(i, i + size));
    return out;
  },

  /** GF(2^n) multiplication used by AES / S-AES MixColumns.
   *  mod = irreducible poly with its leading term stripped (e.g. 0x1B for AES's x^8+x^4+x^3+x+1,
   *  0x03 for S-AES's x^4+x+1), width = bit width. */
  gfMul(a, b, mod, width){
    let p = 0;
    const mask = (1 << width) - 1;
    for (let i = 0; i < width; i++) {
      if (b & 1) p ^= a;
      const hiBitSet = a & (1 << (width - 1));
      a = a << 1;
      if (hiBitSet) a ^= mod;
      a &= mask;
      b >>= 1;
    }
    return p & mask;
  },
};

/* =========================================================
   Step-tree renderer — builds the collapsible "Detail Penyelesaian"
   accordion shared by DES / S-DES / AES / S-AES pages.

   stepTree = [
     { title:'1. Input', body: [ {type:'text', text:'...'}, {type:'bits', label:'Plaintext', value:'...', group:'amber'}, ... ] },
     { title:'Ronde 1', round:true, body:[ ... ] },
     ...
   ]
   ========================================================= */
const StepRenderer = {

  render(stepTree, mountEl){
    mountEl.innerHTML = '';
    stepTree.forEach((step, idx) => {
      const item = document.createElement('div');
      item.className = 'accordion-item' + (step.round ? ' round' : '');
      const head = document.createElement('div');
      head.className = 'accordion-head';
      head.innerHTML = `
        <div class="title"><span class="step-index">${idx + 1}</span> ${step.title}</div>
        <div class="chev">&#9662;</div>`;
      const body = document.createElement('div');
      body.className = 'accordion-body';
      body.innerHTML = step.body.map(b => this.renderBlock(b)).join('');
      head.addEventListener('click', () => item.classList.toggle('open'));
      item.appendChild(head);
      item.appendChild(body);
      mountEl.appendChild(item);
    });
    if (mountEl.firstElementChild) mountEl.firstElementChild.classList.add('open');
  },

  renderBlock(b){
    switch (b.type) {
      case 'text':
        return `<div class="substep"><div class="st-desc">${b.text}</div></div>`;
      case 'sub':
        return `<div class="substep">
          ${b.title ? `<div class="st-title">${b.title}</div>` : ''}
          ${b.desc ? `<div class="st-desc">${b.desc}</div>` : ''}
          ${(b.rows || []).map(r => this.renderBits(r)).join('')}
        </div>`;
      case 'bits':
        return `<div class="substep">${this.renderBits(b)}</div>`;
      case 'matrix':
        return `<div class="substep">${this.renderMatrix(b)}</div>`;
      case 'sbox':
        return `<div class="substep">${this.renderSbox(b)}</div>`;
      case 'note':
        return `<div class="note-callout">${b.text}</div>`;
      case 'hr':
        return `<hr class="div">`;
      default:
        return '';
    }
  },

  renderBits(r){
    const group = r.group ? ` g-${r.group}` : '';
    const wide = r.wide ? ' wide' : '';
    const boxes = (r.chunks || [r.value]).map(v =>
      `<div class="box${group}${wide}">${v}</div>`).join('');
    return `<div>
      ${r.label ? `<div class="st-title" style="color:var(--muted); font-weight:500;">${r.label}${r.meta ? ` <span class="mono" style="color:var(--muted-2);">(${r.meta})</span>` : ''}</div>` : ''}
      <div class="boxrow">${boxes}</div>
    </div>`;
  },

  renderMatrix(m){
    // m.values: array of arrays (row-major), m.cols
    const cols = m.cols || m.values[0].length;
    const cells = m.values.flat().map(v => `<div class="cell">${v}</div>`).join('');
    return `<div>
      ${m.label ? `<div class="st-title" style="color:var(--muted); font-weight:500;">${m.label}</div>` : ''}
      <div class="matrix" style="grid-template-columns:repeat(${cols}, 52px);">${cells}</div>
    </div>`;
  },

  renderSbox(s){
    // s.title, s.rows (array), s.cols (array), s.data (2D), s.hitRow, s.hitCol, s.desc
    let html = `<div class="st-title">${s.title}</div>`;
    if (s.desc) html += `<div class="st-desc">${s.desc}</div>`;
    html += `<table class="sbox"><thead><tr><th></th>${s.cols.map(c => `<th>${c}</th>`).join('')}</tr></thead><tbody>`;
    s.data.forEach((row, ri) => {
      html += `<tr><th>${s.rows[ri]}</th>`;
      row.forEach((val, ci) => {
        let cls = '';
        if (ri === s.hitRow && ci === s.hitCol) cls = 'hit';
        else if (ri === s.hitRow) cls = 'rowhit';
        else if (ci === s.hitCol) cls = 'colhit';
        html += `<td class="${cls}">${val}</td>`;
      });
      html += `</tr>`;
    });
    html += `</tbody></table>`;
    return html;
  }
};

/* ---------- generic module-page wiring ---------- */
function wireModePane(toggleSelector, onChange){
  const btns = document.querySelectorAll(toggleSelector + ' button');
  btns.forEach(b => b.addEventListener('click', () => {
    btns.forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    onChange(b.dataset.mode);
  }));
}

function wireSolutionToggle(toggleId, bodyId){
  const t = document.getElementById(toggleId);
  const b = document.getElementById(bodyId);
  t.addEventListener('click', () => {
    t.classList.toggle('open');
    b.classList.toggle('open');
    t.querySelector('span.label') && (t.querySelector('span.label').textContent =
      t.classList.contains('open') ? 'Sembunyikan Solusi Penyelesaian' : 'Tampilkan Solusi Penyelesaian');
  });
}

function showFieldError(inputEl, errEl, msg){
  if (msg) {
    inputEl.classList.add('invalid');
    errEl.textContent = msg;
    errEl.classList.add('show');
  } else {
    inputEl.classList.remove('invalid');
    errEl.classList.remove('show');
  }
}

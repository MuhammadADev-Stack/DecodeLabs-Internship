const englishFreq = {
  'A': 8.17, 'B': 1.49, 'C': 2.78, 'D': 4.25, 'E': 12.70, 'F': 2.23, 'G': 2.01,
  'H': 6.09, 'I': 6.97, 'J': 0.15, 'K': 0.77, 'L': 4.03, 'M': 2.41, 'N': 6.75,
  'O': 7.51, 'P': 1.93, 'Q': 0.09, 'R': 5.98, 'S': 6.32, 'T': 9.05, 'U': 2.75,
  'V': 0.98, 'W': 2.36, 'X': 0.15, 'Y': 1.97, 'Z': 0.07
};

function mod(n, m) {
  return ((n % m) + m) % m;
}

function updateShiftDisplay() {
  const elem = document.getElementById('caesarShift');
  if (elem) document.getElementById('shiftVal').innerText = elem.value;
}

function switchCipher() {
  const algo = document.getElementById('cipherSelect').value;
  document.getElementById('caesarConfig').classList.toggle('hidden', algo !== 'caesar');
  document.getElementById('vigenereConfig').classList.toggle('hidden', algo !== 'vigenere');
  document.getElementById('xorConfig').classList.toggle('hidden', algo !== 'xor');
  processCrypt();
}

function processCrypt() {
  const inputElem = document.getElementById('inputText');
  const input = inputElem ? inputElem.value : '';
  const algo = document.getElementById('cipherSelect').value;

  let encrypted = "";
  let decrypted = "";

  if (algo === 'caesar') {
    const rawShift = parseInt(document.getElementById('caesarShift').value, 10);
    const shift = isNaN(rawShift) ? 0 : rawShift;
    
    encrypted = caesarTransform(input, shift);
    decrypted = caesarTransform(encrypted, -shift);
    updatePipeline(input[0] || 'A', shift);
  } else if (algo === 'vigenere') {
    const key = document.getElementById('vigenereKey').value || 'KEY';
    encrypted = vigenereTransform(input, key, 'encrypt');
    decrypted = vigenereTransform(encrypted, key, 'decrypt');
    updatePipelineVigenere(input[0] || 'A', key[0] || 'K');
  } else if (algo === 'xor') {
    const rawKey = document.getElementById('xorKey').value;
    const key = (rawKey !== '' && !isNaN(rawKey)) ? parseInt(rawKey, 10) : 142;
    
    encrypted = xorTransform(input, key);
    decrypted = xorDecryptFromHex(encrypted, key);
    updatePipelineXOR(input[0] || 'A', key);
  }

  document.getElementById('outputText').innerText = encrypted || '[NO OUTPUT]';
  document.getElementById('decryptedText').innerText = decrypted || '[NO OUTPUT]';
  renderFrequencyChart(encrypted);
}

function caesarTransform(str, shift) {
  return str.split('').map(char => {
    const code = char.charCodeAt(0);
    if (code >= 65 && code <= 90) return String.fromCharCode(mod(code - 65 + shift, 26) + 65);
    if (code >= 97 && code <= 122) return String.fromCharCode(mod(code - 97 + shift, 26) + 97);
    return char;
  }).join('');
}

function vigenereTransform(str, key, mode) {
  let result = "";
  let keyIdx = 0;
  const cleanKey = key.toUpperCase().replace(/[^A-Z]/g, '') || "A";

  for (let i = 0; i < str.length; i++) {
    let code = str.charCodeAt(i);
    let shift = cleanKey[keyIdx % cleanKey.length].charCodeAt(0) - 65;
    if (mode === 'decrypt') shift = mod(-shift, 26);

    if (code >= 65 && code <= 90) {
      result += String.fromCharCode(mod(code - 65 + shift, 26) + 65);
      keyIdx++;
    } else if (code >= 97 && code <= 122) {
      result += String.fromCharCode(mod(code - 97 + shift, 26) + 97);
      keyIdx++;
    } else {
      result += str[i];
    }
  }
  return result;
}

function xorTransform(str, key) {
  return str.split('').map(char => (char.charCodeAt(0) ^ key).toString(16).padStart(2, '0').toUpperCase()).join(' ');
}

function xorDecryptFromHex(hexStr, key) {
  const hexes = hexStr.split(' ').filter(h => h.trim() !== '');
  return hexes.map(hex => String.fromCharCode(parseInt(hex, 16) ^ key)).join('');
}

function updatePipeline(char, shift) {
  const code = char.toUpperCase().charCodeAt(0);
  const isAlpha = code >= 65 && code <= 90;
  const norm = isAlpha ? code - 65 : 0;
  const shiftedMod = isAlpha ? mod(norm + shift, 26) : 0;
  const outChar = isAlpha ? String.fromCharCode(shiftedMod + 65) : char;

  document.getElementById('flowPipeline').innerHTML = `
    <div class="flex justify-between"><span class="text-cyan-300/70">1. INPUT CHAR:</span> <span class="text-white font-bold">'${char}'</span></div>
    <div class="flex justify-between"><span class="text-cyan-300/70">2. ASCII CONVERT:</span> <span class="text-cyan-200">${code}</span></div>
    <div class="flex justify-between"><span class="text-cyan-300/70">3. BASE SHIFT (-65):</span> <span class="text-cyan-200">${norm}</span></div>
    <div class="flex justify-between"><span class="text-cyan-300/70">4. MODULO (${shift} Shift % 26):</span> <span class="text-amber-300 font-bold">${shiftedMod}</span></div>
    <div class="flex justify-between border-t border-cyan-400/40 pt-1"><span class="text-cyan-300/70">5. CIPHER OUTPUT:</span> <span class="text-emerald-300 font-bold">'${outChar}' (${shiftedMod + 65})</span></div>
  `;
}

function updatePipelineVigenere(char, keyChar) {
  const cCode = char.toUpperCase().charCodeAt(0);
  const kCode = keyChar.toUpperCase().charCodeAt(0);
  const cNorm = (cCode >= 65 && cCode <= 90) ? cCode - 65 : 0;
  const kNorm = (kCode >= 65 && kCode <= 90) ? kCode - 65 : 0;
  const modVal = mod(cNorm + kNorm, 26);

  document.getElementById('flowPipeline').innerHTML = `
    <div class="flex justify-between"><span class="text-cyan-300/70">1. INPUT CHAR:</span> <span class="text-white font-bold">'${char}' (${cNorm})</span></div>
    <div class="flex justify-between"><span class="text-cyan-300/70">2. KEY BYTE:</span> <span class="text-cyan-200">'${keyChar}' (${kNorm})</span></div>
    <div class="flex justify-between"><span class="text-cyan-300/70">3. SHIFT CALCULATION:</span> <span class="text-amber-300 font-bold">(${cNorm} + ${kNorm}) % 26 = ${modVal}</span></div>
    <div class="flex justify-between border-t border-cyan-400/40 pt-1"><span class="text-cyan-300/70">4. POLY-SUBSTITUTED:</span> <span class="text-emerald-300 font-bold">'${String.fromCharCode(modVal + 65)}' (${modVal + 65})</span></div>
  `;
}

function updatePipelineXOR(char, key) {
  const code = char.charCodeAt(0);
  const xored = code ^ key;
  document.getElementById('flowPipeline').innerHTML = `
    <div class="flex justify-between"><span class="text-cyan-300/70">1. ASCII CODE:</span> <span class="text-white font-bold">${code}</span></div>
    <div class="flex justify-between"><span class="text-cyan-300/70">2. BITWISE KEY:</span> <span class="text-cyan-200">${key}</span></div>
    <div class="flex justify-between"><span class="text-cyan-300/70">3. XOR STREAM:</span> <span class="text-amber-300 font-bold">${xored}</span></div>
    <div class="flex justify-between border-t border-cyan-400/40 pt-1"><span class="text-cyan-300/70">4. HEX ENCODING:</span> <span class="text-emerald-300 font-bold">0x${xored.toString(16).toUpperCase()}</span></div>
  `;
}

function renderFrequencyChart(text) {
  const counts = {};
  let total = 0;
  const clean = text.toUpperCase().replace(/[^A-Z]/g, '');

  for (let c of clean) {
    counts[c] = (counts[c] || 0) + 1;
    total++;
  }

  const container = document.getElementById('freqChart');
  if (!container) return;
  container.innerHTML = '';

  "ABCDEFGHIJKLMNOPQRSTUVWXYZ".split('').forEach(letter => {
    const count = counts[letter] || 0;
    const pct = total > 0 ? (count / total) * 100 : 0;
    const barHeight = Math.min(Math.max(pct * 3, 4), 100);

    const bar = document.createElement('div');
    bar.className = 'w-full bg-cyan-400 hover:bg-white relative group border-t border-cyan-200 cursor-pointer';
    bar.style.height = `${barHeight}%`;
    bar.innerHTML = `<div class="hidden group-hover:block absolute -top-7 left-1/2 -translate-x-1/2 bg-slate-950 border border-cyan-300 text-[10px] text-cyan-200 px-1.5 py-0.5 whitespace-nowrap z-10 font-mono shadow-md">${letter}: ${pct.toFixed(1)}%</div>`;
    container.appendChild(bar);
  });
}

function runBruteForce() {
  const ciphertext = document.getElementById('outputText').innerText;
  const container = document.getElementById('bruteResults');
  if (!container) return;
  container.innerHTML = '';

  let candidates = [];
  for (let s = 1; s < 26; s++) {
    const decrypted = caesarTransform(ciphertext, -s);
    const score = calculateChiSquare(decrypted);
    candidates.push({ shift: s, text: decrypted, score: score });
  }

  candidates.sort((a, b) => a.score - b.score);
  candidates.forEach((item, idx) => {
    const row = document.createElement('div');
    row.className = `flex justify-between items-center p-1 font-mono text-xs ${idx === 0 ? 'bg-cyan-500/30 text-white border-l-4 border-cyan-300 font-bold' : 'text-cyan-100 border-b border-cyan-900/50'}`;
    row.innerHTML = `
      <span>[KEY +${item.shift.toString().padStart(2, '0')}] ${item.text.substring(0, 30)}...</span>
      <span class="${idx === 0 ? 'text-emerald-300 font-bold' : 'text-cyan-400'}">Chi²: ${item.score.toFixed(1)}</span>
    `;
    container.appendChild(row);
  });
}

window.onload = processCrypt;
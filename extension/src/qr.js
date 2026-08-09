// Small self-contained QR encoder for ASCII Telegram links. It emits Version 5-L QR codes,
// which fit the longest URL allowed by the backend contract (106 bytes).
const VERSION = 5;
const SIZE = VERSION * 4 + 17;
const DATA_CODEWORDS = 108;
const ECC_CODEWORDS = 26;
const MASK = 3;

export function renderTelegramQr(svg, telegramUrl) {
  const bytes = new TextEncoder().encode(telegramUrl);
  if (bytes.length > 106) {
    throw new Error("Telegram URL is too long for the bundled QR encoder");
  }
  const modules = encode(bytes);
  const quiet = 4;
  const viewBoxSize = SIZE + quiet * 2;
  const rectangles = [];
  for (let y = 0; y < SIZE; y += 1) {
    for (let x = 0; x < SIZE; x += 1) {
      if (modules[y][x]) {
        rectangles.push(`<rect x="${x + quiet}" y="${y + quiet}" width="1" height="1"/>`);
      }
    }
  }
  svg.setAttribute("viewBox", `0 0 ${viewBoxSize} ${viewBoxSize}`);
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "QR-код для открытия Telegram");
  svg.innerHTML = `<rect width="${viewBoxSize}" height="${viewBoxSize}" fill="#fff"/>`
    + `<g fill="#080808">${rectangles.join("")}</g>`;
}

export function encodeTelegramQr(telegramUrl) {
  const bytes = new TextEncoder().encode(telegramUrl);
  if (bytes.length > 106) {
    throw new Error("Telegram URL is too long for the bundled QR encoder");
  }
  return encode(bytes);
}

function encode(bytes) {
  const data = makeDataCodewords(bytes);
  const ecc = reedSolomonRemainder(data, reedSolomonDivisor(ECC_CODEWORDS));
  const codewords = [...data, ...ecc];
  const modules = Array.from({length: SIZE}, () => Array(SIZE).fill(false));
  const functionModules = Array.from({length: SIZE}, () => Array(SIZE).fill(false));

  const setFunction = (x, y, value) => {
    modules[y][x] = value;
    functionModules[y][x] = true;
  };
  drawFinder(setFunction, 3, 3);
  drawFinder(setFunction, SIZE - 4, 3);
  drawFinder(setFunction, 3, SIZE - 4);
  drawAlignment(setFunction, 30, 30);
  for (let index = 8; index < SIZE - 8; index += 1) {
    if (!functionModules[6][index]) setFunction(index, 6, index % 2 === 0);
    if (!functionModules[index][6]) setFunction(6, index, index % 2 === 0);
  }
  reserveFormat(setFunction);
  drawCodewords(modules, functionModules, codewords);
  drawFormat(setFunction);
  return modules;
}

function makeDataCodewords(bytes) {
  const bits = [];
  appendBits(bits, 0b0100, 4);
  appendBits(bits, bytes.length, 8);
  for (const byte of bytes) appendBits(bits, byte, 8);
  const capacity = DATA_CODEWORDS * 8;
  appendBits(bits, 0, Math.min(4, capacity - bits.length));
  while (bits.length % 8 !== 0) bits.push(0);
  const result = [];
  for (let index = 0; index < bits.length; index += 8) {
    let value = 0;
    for (let bit = 0; bit < 8; bit += 1) value = (value << 1) | bits[index + bit];
    result.push(value);
  }
  for (let pad = 0; result.length < DATA_CODEWORDS; pad += 1) {
    result.push(pad % 2 === 0 ? 0xec : 0x11);
  }
  return result;
}

function appendBits(target, value, length) {
  for (let bit = length - 1; bit >= 0; bit -= 1) target.push((value >>> bit) & 1);
}

function drawFinder(setFunction, centerX, centerY) {
  for (let dy = -4; dy <= 4; dy += 1) {
    for (let dx = -4; dx <= 4; dx += 1) {
      const x = centerX + dx;
      const y = centerY + dy;
      if (x < 0 || y < 0 || x >= SIZE || y >= SIZE) continue;
      const distance = Math.max(Math.abs(dx), Math.abs(dy));
      setFunction(x, y, distance !== 2 && distance !== 4);
    }
  }
}

function drawAlignment(setFunction, centerX, centerY) {
  for (let dy = -2; dy <= 2; dy += 1) {
    for (let dx = -2; dx <= 2; dx += 1) {
      setFunction(centerX + dx, centerY + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  }
}

function reserveFormat(setFunction) {
  for (let index = 0; index <= 8; index += 1) {
    if (index !== 6) {
      setFunction(8, index, false);
      setFunction(index, 8, false);
    }
  }
  for (let index = 0; index < 8; index += 1) setFunction(SIZE - 1 - index, 8, false);
  for (let index = 0; index < 7; index += 1) setFunction(8, SIZE - 1 - index, false);
  setFunction(8, SIZE - 8, true);
}

function drawCodewords(modules, functionModules, codewords) {
  let bitIndex = 0;
  for (let right = SIZE - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    const upward = ((right + 1) & 2) === 0;
    for (let vertical = 0; vertical < SIZE; vertical += 1) {
      const y = upward ? SIZE - 1 - vertical : vertical;
      for (let offset = 0; offset < 2; offset += 1) {
        const x = right - offset;
        if (functionModules[y][x]) continue;
        let value = false;
        if (bitIndex < codewords.length * 8) {
          value = ((codewords[bitIndex >>> 3] >>> (7 - (bitIndex & 7))) & 1) !== 0;
          bitIndex += 1;
        }
        if ((x + y) % 3 === 0) value = !value;
        modules[y][x] = value;
      }
    }
  }
}

function drawFormat(setFunction) {
  const data = (1 << 3) | MASK; // Error correction level L is binary 01.
  let remainder = data << 10;
  for (let bit = 14; bit >= 10; bit -= 1) {
    if (((remainder >>> bit) & 1) !== 0) remainder ^= 0x537 << (bit - 10);
  }
  const bits = ((data << 10) | remainder) ^ 0x5412;
  const value = (index) => ((bits >>> index) & 1) !== 0;
  for (let index = 0; index <= 5; index += 1) setFunction(8, index, value(index));
  setFunction(8, 7, value(6));
  setFunction(8, 8, value(7));
  setFunction(7, 8, value(8));
  for (let index = 9; index < 15; index += 1) setFunction(14 - index, 8, value(index));
  for (let index = 0; index < 8; index += 1) setFunction(SIZE - 1 - index, 8, value(index));
  for (let index = 8; index < 15; index += 1) setFunction(8, SIZE - 15 + index, value(index));
  setFunction(8, SIZE - 8, true);
}

function reedSolomonDivisor(degree) {
  let polynomial = [1];
  let root = 1;
  for (let index = 0; index < degree; index += 1) {
    const next = Array(polynomial.length + 1).fill(0);
    for (let term = 0; term < polynomial.length; term += 1) {
      next[term] ^= polynomial[term];
      next[term + 1] ^= multiply(polynomial[term], root);
    }
    polynomial = next;
    root = multiply(root, 2);
  }
  return polynomial;
}

function reedSolomonRemainder(data, divisor) {
  const message = [...data, ...Array(divisor.length - 1).fill(0)];
  for (let index = 0; index < data.length; index += 1) {
    const factor = message[index];
    if (factor === 0) continue;
    for (let term = 0; term < divisor.length; term += 1) {
      message[index + term] ^= multiply(divisor[term], factor);
    }
  }
  return message.slice(data.length);
}

function multiply(left, right) {
  let result = 0;
  let x = left;
  let y = right;
  while (y !== 0) {
    if (y & 1) result ^= x;
    y >>>= 1;
    x = (x << 1) ^ ((x >>> 7) * 0x11d);
  }
  return result;
}

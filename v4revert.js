#!/usr/bin/env node
// Decode Uniswap v4 revert data, unwrapping nested WrappedError / ExecutionFailed layers.
'use strict';

// keccak-256 (node:crypto's sha3-256 uses different padding, so it can't produce selectors)
const RC = '0000000000000001 0000000000008082 800000000000808a 8000000080008000 000000000000808b 0000000080000001 8000000080008081 8000000000008009 000000000000008a 0000000000000088 0000000080008009 000000008000000a 000000008000808b 800000000000008b 8000000000008089 8000000000008003 8000000000008002 8000000000000080 000000000000800a 800000008000000a 8000000080008081 8000000000008080 0000000080000001 8000000080008008'.split(' ').map((h) => BigInt('0x' + h));
const ROT = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
const PIL = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];
const M64 = (1n << 64n) - 1n;
const rotl = (x, n) => ((x << BigInt(n)) | (x >> BigInt(64 - n))) & M64;

function keccakF(s) {
  for (const rc of RC) {
    const c = [0, 1, 2, 3, 4].map((x) => s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20]);
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
      for (let y = 0; y < 25; y += 5) s[x + y] ^= d;
    }
    let t = s[1];
    for (let i = 0; i < 24; i++) [s[PIL[i]], t] = [rotl(t, ROT[i]), s[PIL[i]]];
    for (let y = 0; y < 25; y += 5) {
      const row = s.slice(y, y + 5);
      for (let x = 0; x < 5; x++) s[y + x] = row[x] ^ (~row[(x + 1) % 5] & M64 & row[(x + 2) % 5]);
    }
    s[0] ^= rc;
  }
}

function keccak256(input) {
  const RATE = 136;
  const msg = Buffer.from(input);
  const padded = Buffer.alloc(msg.length + RATE - (msg.length % RATE));
  msg.copy(padded);
  padded[msg.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  const s = new Array(25).fill(0n);
  for (let off = 0; off < padded.length; off += RATE) {
    for (let i = 0; i < RATE / 8; i++) s[i] ^= padded.readBigUInt64LE(off + i * 8);
    keccakF(s);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) out.writeBigUInt64LE(s[i], i * 8);
  return out;
}

const selectorOf = (sig) => keccak256(sig).subarray(0, 4).toString('hex');

const PANIC = {
  0x01: 'assert failed', 0x11: 'arithmetic overflow/underflow', 0x12: 'division by zero',
  0x21: 'invalid enum value', 0x22: 'bad storage byte array', 0x31: 'pop on empty array',
  0x32: 'array index out of bounds', 0x41: 'out of memory', 0x51: 'uninitialized function pointer',
};

const ERRORS = [
  'Error(string)', 'Panic(uint256)',
  // CustomRevert (v4-core)
  'WrappedError(address target, bytes4 selector, bytes reason, bytes details)',
  // IPoolManager / IHooks
  'CurrencyNotSettled()', 'AlreadyUnlocked()', 'ManagerLocked()', 'ProtocolFeeTooLarge(uint24 fee)',
  'TickSpacingTooLarge(int24 tickSpacing)', 'TickSpacingTooSmall(int24 tickSpacing)',
  'CurrenciesOutOfOrderOrEqual(address currency0, address currency1)', 'UnauthorizedDynamicLPFeeUpdate()',
  'SwapAmountCannotBeZero()', 'NonzeroNativeValue()', 'MustClearExactPositiveDelta()',
  'HookAddressNotValid(address hooks)', 'InvalidHookResponse()', 'HookCallFailed()', 'HookDeltaExceedsSwapAmount()',
  // Pool / TickMath / SqrtPriceMath / LPFeeLibrary / Position / CurrencyLibrary
  'TicksMisordered(int24 tickLower, int24 tickUpper)', 'TickLowerOutOfBounds(int24 tickLower)',
  'TickUpperOutOfBounds(int24 tickUpper)', 'TickLiquidityOverflow(int24 tick)', 'PoolAlreadyInitialized()',
  'PoolNotInitialized()', 'PriceLimitAlreadyExceeded(uint160 sqrtPriceCurrentX96, uint160 sqrtPriceLimitX96)',
  'PriceLimitOutOfBounds(uint160 sqrtPriceLimitX96)', 'NoLiquidity()', 'InvalidFeeForExactOut()',
  'InvalidTick(int24 tick)', 'InvalidSqrtPrice(uint160 sqrtPriceX96)', 'InvalidPriceOrLiquidity()', 'InvalidPrice()',
  'NotEnoughLiquidity()', 'PriceOverflow()', 'LPFeeTooLarge(uint24 fee)', 'CannotUpdateEmptyPosition()',
  'NativeTransferFailed()', 'ERC20TransferFailed()', 'SafeCastOverflow()',
  // v4-periphery routers
  'V4TooLittleReceived(uint256 minAmountOutReceived, uint256 amountReceived)',
  'V4TooMuchRequested(uint256 maxAmountInRequested, uint256 amountRequested)',
  'DeltaNotPositive(address currency)', 'DeltaNotNegative(address currency)', 'ContractLocked()',
  'UnsupportedAction(uint256 action)',
  // Universal Router / Permit2
  'ExecutionFailed(uint256 commandIndex, bytes message)', 'TransactionDeadlinePassed()',
  'V2TooLittleReceived()', 'V3TooLittleReceived()', 'InsufficientAllowance(uint256 amount)',
  'AllowanceExpired(uint256 deadline)',
];

const POOL_KEY = '(address,address,uint24,int24,address)';
const LIQUIDITY = '(int24,int24,int256,bytes32)';
const SWAP = '(bool,int256,uint160)';
const HOOKS = {};
for (const sig of [
  `beforeInitialize(address,${POOL_KEY},uint160)`,
  `afterInitialize(address,${POOL_KEY},uint160,int24)`,
  `beforeAddLiquidity(address,${POOL_KEY},${LIQUIDITY},bytes)`,
  `afterAddLiquidity(address,${POOL_KEY},${LIQUIDITY},int256,int256,bytes)`,
  `beforeRemoveLiquidity(address,${POOL_KEY},${LIQUIDITY},bytes)`,
  `afterRemoveLiquidity(address,${POOL_KEY},${LIQUIDITY},int256,int256,bytes)`,
  `beforeSwap(address,${POOL_KEY},${SWAP},bytes)`,
  `afterSwap(address,${POOL_KEY},${SWAP},int256,bytes)`,
  `beforeDonate(address,${POOL_KEY},uint256,uint256,bytes)`,
  `afterDonate(address,${POOL_KEY},uint256,uint256,bytes)`,
]) HOOKS[selectorOf(sig)] = sig.slice(0, sig.indexOf('('));

function parseSig(sig) {
  const m = sig.trim().replace(/^error\s+/, '').replace(/;$/, '').match(/^(\w+)\((.*)\)$/);
  if (!m) throw new Error(`bad signature: ${sig}`);
  const params = m[2].trim() ? m[2].split(',').map((p, i) => {
    const [type, name] = p.trim().split(/\s+/);
    return { type: type === 'uint' ? 'uint256' : type === 'int' ? 'int256' : type, name: name ?? `arg${i}` };
  }) : [];
  return { name: m[1], params, selector: selectorOf(`${m[1]}(${params.map((p) => p.type).join(',')})`) };
}

const word = (data, off) => {
  if (off + 32 > data.length) throw new Error('truncated');
  return data.subarray(off, off + 32);
};
const uint = (buf) => BigInt('0x' + buf.toString('hex'));

function readParam(type, data, slot) {
  const w = word(data, slot * 32);
  if (type === 'bytes' || type === 'string') {
    const off = Number(uint(w));
    const len = Number(uint(word(data, off)));
    if (off + 32 + len > data.length) throw new Error('truncated');
    const raw = data.subarray(off + 32, off + 32 + len);
    return type === 'string' ? raw.toString('utf8') : raw;
  }
  if (type === 'address') return '0x' + w.subarray(12).toString('hex');
  if (type === 'bool') return uint(w) !== 0n;
  let m;
  if ((m = type.match(/^uint(\d*)$/))) return uint(w);
  if ((m = type.match(/^int(\d*)$/))) return BigInt.asIntN(Number(m[1] || 256), uint(w));
  if ((m = type.match(/^bytes(\d+)$/))) return '0x' + w.subarray(0, Number(m[1])).toString('hex');
  throw new Error(`unsupported type: ${type}`); // ponytail: no arrays/tuples, none of the known errors need them
}

// Returns a tree: { name, args: [{ name, value }], raw? }; unknown or malformed data stays raw hex.
function decode(data, extra = []) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data).trim().replace(/^0x/, ''), 'hex');
  const hex = '0x' + buf.toString('hex');
  if (buf.length === 0) return { name: 'empty', args: [] };
  if (buf.length < 4) return { name: 'unknown', raw: hex, args: [] };
  const known = [...extra, ...ERRORS].map(parseSig).find((e) => e.selector === buf.toString('hex', 0, 4));
  if (!known) return { name: 'unknown', raw: hex, args: [] };
  const body = buf.subarray(4);
  try {
    const args = known.params.map((p, i) => {
      const value = readParam(p.type, body, i);
      return { name: p.name, value: p.type === 'bytes' ? decode(value, extra) : value };
    });
    return { name: known.name, args };
  } catch {
    return { name: known.name, raw: hex, args: [] };
  }
}

function render(node, indent = '') {
  if (node.name === 'empty') return '(empty revert data)';
  if (node.raw) return `${node.name === 'unknown' ? 'unknown' : node.name + ' (malformed)'} ${node.raw}`;
  if (node.name === 'Error') return `Error(${JSON.stringify(node.args[0].value)})`;
  if (node.name === 'Panic') {
    const code = node.args[0].value;
    return `Panic(0x${code.toString(16)}: ${PANIC[Number(code)] ?? 'unknown code'})`;
  }
  if (!node.args.length) return `${node.name}()`;
  const lines = node.args.map(({ name, value }) => {
    let text = value?.args ? render(value, indent + '  ') : String(value);
    if (name === 'selector' && HOOKS[text.slice(2)]) text += ` (${HOOKS[text.slice(2)]})`;
    return `${indent}  ${name}: ${text}`;
  });
  return [node.name, ...lines].join('\n');
}

if (require.main === module) {
  const args = process.argv.slice(2);
  const sigs = [];
  let input;
  while (args.length) {
    const a = args.shift();
    if (a === '--sig') sigs.push(args.shift());
    else if (a === '-h' || a === '--help') {
      console.log('usage: v4revert [--sig "MyError(uint256 cap)"]... <0xrevertdata>\n       (reads stdin if no data is given)');
      process.exit(0);
    } else input = a;
  }
  input ??= require('fs').readFileSync(0, 'utf8');
  const hex = input.trim().replace(/^0x/, '');
  if (!/^([0-9a-fA-F]{2})*$/.test(hex)) {
    console.error('error: input is not hex revert data');
    process.exit(1);
  }
  console.log(render(decode(hex, sigs)));
}

module.exports = { decode, render, keccak256, selectorOf };

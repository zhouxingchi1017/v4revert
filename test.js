const assert = require('assert');
const { execFileSync } = require('child_process');
const { decode, render, keccak256, selectorOf } = require('./v4revert');

const pad = (hex) => hex.padStart(64, '0');
const padR = (hex) => hex.padEnd(Math.ceil(hex.length / 64) * 64 || 0, '0');
const dyn = (hex) => pad((hex.length / 2).toString(16)) + padR(hex);
const str = (s) => Buffer.from(s).toString('hex');
const errorString = (s) => '08c379a0' + pad('20') + dyn(str(s));

// keccak test vectors and selectors published in the wild
assert.equal(keccak256('').toString('hex'), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
assert.equal(keccak256('a'.repeat(136)).length, 32); // padding on an exact rate boundary
assert.equal(selectorOf('transfer(address,uint256)'), 'a9059cbb');
assert.equal(selectorOf('Error(string)'), '08c379a0');
assert.equal(selectorOf('WrappedError(address,bytes4,bytes,bytes)'), '90bfb865');
assert.equal(selectorOf('HookCallFailed()'), 'a9e35b2f');

const reason = errorString('wallet cap exceeded');
const details = 'a9e35b2f';
const target = '1111111111111111111111111111111111110088';
const wrapped = '90bfb865' + pad(target) + padR('575e24b4') + pad('80')
  + pad((0x80 + 32 + reason.length / 2 + (32 - (reason.length / 2) % 32) % 32).toString(16))
  + dyn(reason) + dyn(details);

const tree = decode(wrapped);
assert.equal(tree.name, 'WrappedError');
assert.equal(tree.args[0].value, '0x' + target);
assert.equal(tree.args[2].value.args[0].value, 'wallet cap exceeded');
assert.equal(tree.args[3].value.name, 'HookCallFailed');
const text = render(tree);
assert.ok(text.includes('(beforeSwap)'), text);
assert.ok(text.includes('reason: Error("wallet cap exceeded")'), text);

// Universal Router -> WrappedError -> Error(string): nesting indents one level per layer
const outer = '2c4029e9' + pad('0') + pad('40') + dyn(wrapped);
const nested = render(decode(outer));
assert.ok(nested.startsWith('ExecutionFailed\n  commandIndex: 0\n  message: WrappedError\n    target: 0x'), nested);

// custom hook error via --sig, including a negative int
const customSig = 'V4Nope(int24 tick, address who)';
const custom = selectorOf('V4Nope(int24,address)') + 'f'.repeat(64) + pad(target);
assert.equal(decode(custom).name, 'unknown');
assert.equal(decode(custom, [customSig]).args[0].value, -1n);

assert.equal(render(decode('0x')), '(empty revert data)');
assert.equal(render(decode('0x4e487b71' + pad('11'))), 'Panic(0x11: arithmetic overflow/underflow)');
assert.equal(render(decode('0xdeadbeef')), 'unknown 0xdeadbeef');
assert.equal(render(decode('0x08c379a0' + pad('20'))), 'Error (malformed) 0x08c379a0' + pad('20')); // truncated, must not throw

const cli = execFileSync('node', ['v4revert.js', '0x' + wrapped], { cwd: __dirname, encoding: 'utf8' });
assert.ok(cli.startsWith('WrappedError\n'), cli);
console.log('ok');

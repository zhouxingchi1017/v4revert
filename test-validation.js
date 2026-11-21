'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { decode, selectorOf } = require('./v4revert');
const word = n => BigInt(n).toString(16).padStart(64, '0');

for (const input of ['0xzz', '0x123', '12xx34', '0X12']) {
  test(`reject invalid hex: ${input}`, () => {
    assert.throws(() => decode(input), /input is not hex revert data/);
  });
}

for (const offset of [0n, 1n, 31n, 33n, 1n << 255n]) {
  test(`reject invalid dynamic offset: ${offset}`, () => {
    const input = '0x08c379a0' + word(offset) + word(0);
    assert.deepEqual(decode(input), { name: 'Error', raw: input, args: [] });
  });
}

test('offset must follow the entire argument head', () => {
  const input = '0x' + selectorOf('Example(uint256,string)') + word(0) + word(32);
  assert.deepEqual(decode(input, ['Example(uint256,string)']), {
    name: 'Example', raw: input, args: [],
  });
});

test('oversized dynamic length remains malformed', () => {
  const input = '0x08c379a0' + word(32) + word(1n << 255n);
  assert.deepEqual(decode(input), { name: 'Error', raw: input, args: [] });
});

test('valid empty and nonempty strings decode from hex and buffers', () => {
  for (const text of ['', 'paused']) {
    const data = Buffer.from(text);
    const input = '08c379a0' + word(32) + word(data.length)
      + data.toString('hex').padEnd(Math.ceil(data.length / 32) * 64, '0');
    for (const value of [input, '0x' + input, Buffer.from(input, 'hex')]) {
      assert.equal(decode(value).args[0].value, text);
    }
  }
  assert.equal(decode('0x').name, 'empty');
});

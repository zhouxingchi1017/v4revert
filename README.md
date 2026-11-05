# v4revert

Uniswap v4 hides the real revert. When a hook fails, PoolManager wraps it in `WrappedError(address,bytes4,bytes,bytes)` (`0x90bfb865`), the Universal Router may wrap that again in `ExecutionFailed`, and your tooling prints a useless blob, or `execution reverted`.

`v4revert` peels every layer. One file, zero dependencies, works offline.

```bash
npx github:zhouxingchi1017/v4revert 0x90bfb8650000000000000000000000001111111111111111111111111111111111110088575e24b40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000006408c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001377616c6c65742063617020657863656564656400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004a9e35b2f00000000000000000000000000000000000000000000000000000000
```

```
WrappedError
  target: 0x1111111111111111111111111111111111110088
  selector: 0x575e24b4 (beforeSwap)
  reason: Error("wallet cap exceeded")
  details: HookCallFailed()
```

## Usage

```bash
v4revert 0x90bfb865...                                # argument
echo 0x90bfb865... | v4revert                        # stdin
v4revert --sig 'WalletCap(uint256 cap)' 0x...         # your hook's custom errors (repeatable)
```

Decodes `Error(string)`, `Panic(uint256)`, v4-core and v4-periphery errors, Universal Router and Permit2 errors, and names the hook callback in `WrappedError.selector`. Unknown selectors are printed as raw hex: pass them in with `--sig`.

## Library

```js
const { decode, render } = require('v4revert');
console.log(render(decode(revertData, ['WalletCap(uint256 cap)'])));
```

## Test

```bash
node test.js
```

## License

MIT

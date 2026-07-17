'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const outputDir = path.resolve(process.argv[2] || path.join(__dirname, '..', 'output'));
const variants = [
  {
    name: 'SIMD',
    js: path.join(outputDir, 'SalviumWallet.js'),
    wasm: path.join(outputDir, 'SalviumWallet.wasm'),
    simdMarker: '[SIMD:ON]',
  },
  {
    name: 'baseline',
    js: path.join(outputDir, 'SalviumWalletBaseline.js'),
    wasm: path.join(outputDir, 'SalviumWalletBaseline.wasm'),
    simdMarker: '[SIMD:OFF]',
  },
];

function moduleInterface(bytes) {
  const module = new WebAssembly.Module(bytes);
  return {
    imports: WebAssembly.Module.imports(module),
    exports: WebAssembly.Module.exports(module),
  };
}

function semanticImportNames(jsFile) {
  const glue = fs.readFileSync(jsFile, 'utf8');
  const match = glue.match(/var wasmImports=\{([^}]*)\};var wasmExports/);
  assert(match, `Unable to locate wasmImports in ${jsFile}`);
  return match[1]
    .split(',')
    .map((entry) => entry.slice(entry.indexOf(':') + 1))
    .sort();
}

async function load(variant) {
  const bytes = fs.readFileSync(variant.wasm);
  assert.strictEqual(WebAssembly.validate(bytes), true, `${variant.name} WASM is invalid`);

  const factory = require(variant.js);
  const instance = await factory({
    wasmBinary: bytes,
    noInitialRun: true,
    print() {},
    printErr() {},
  });

  assert.strictEqual(typeof instance._donna64_get_version, 'function');
  assert.strictEqual(typeof instance.ccall, 'function');
  assert.strictEqual(typeof instance.get_version, 'function');
  assert.strictEqual(typeof instance.WasmWallet, 'function');
  for (const obsoleteExport of [
    'WalletWasm',
    'WalletError',
    'VectorCachedBlock',
    'VectorString',
    'VectorTransferInfo',
    'Donna64Scanner',
    'donna64_debug_get_byte',
    'donna64_debug_test',
  ]) {
    assert.strictEqual(
      instance[obsoleteExport],
      undefined,
      `Obsolete or diagnostic API ${obsoleteExport} must not be exported`,
    );
  }

  const directDonnaVersion = instance._donna64_get_version();
  const ccallDonnaVersion = instance.ccall('donna64_get_version', 'number', [], []);
  assert.strictEqual(directDonnaVersion, ccallDonnaVersion);

  const runtimeVersion = instance.get_version();
  assert.match(
    runtimeVersion,
    /5\.54\.11-hf14-v113c/,
  );
  assert.match(runtimeVersion, new RegExp(variant.simdMarker.replace(/[[\]]/g, '\\$&')));

  return {
    interface: moduleInterface(bytes),
    semanticImports: semanticImportNames(variant.js),
    moduleKeys: Object.keys(instance).sort(),
    donnaVersion: directDonnaVersion,
    runtimeVersion,
  };
}

async function main() {
  const simd = await load(variants[0]);
  const baseline = await load(variants[1]);
  const simdImports = new Set(simd.semanticImports);
  const baselineOnlyImports = baseline.semanticImports.filter((name) => !simdImports.has(name));

  assert.deepStrictEqual(baselineOnlyImports, ['_emscripten_memcpy_js']);
  assert.strictEqual(baseline.interface.imports.length, simd.interface.imports.length + 1);
  // Internal export names are minified independently and are not stable across
  // the SIMD and baseline links. Their kinds/counts and the public module keys
  // below are the meaningful parity checks.
  assert.strictEqual(baseline.interface.exports.length, simd.interface.exports.length);
  assert.deepStrictEqual(
    baseline.interface.exports.map(({ kind }) => kind).sort(),
    simd.interface.exports.map(({ kind }) => kind).sort(),
  );
  assert.deepStrictEqual(baseline.moduleKeys, simd.moduleKeys);
  assert.strictEqual(baseline.donnaVersion, simd.donnaVersion);

  console.log(JSON.stringify({
    valid: true,
    wasmImports: {
      simd: simd.interface.imports.length,
      baseline: baseline.interface.imports.length,
      baselineOnly: baselineOnlyImports,
    },
    wasmExports: simd.interface.exports.length,
    moduleApiKeys: simd.moduleKeys.length,
    donna64Version: simd.donnaVersion,
    runtimeVersions: {
      simd: simd.runtimeVersion,
      baseline: baseline.runtimeVersion,
    },
    publicApiParity: true,
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

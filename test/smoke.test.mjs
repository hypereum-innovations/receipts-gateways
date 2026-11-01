// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire, registerHooks } from 'node:module';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const tcModules = '/tmp/toolchains/node_modules';
const req = createRequire(
  fs.existsSync(path.join(tcModules, 'typescript/package.json'))
    ? path.join(tcModules, 'typescript/package.json')
    : import.meta.url,
);
const ts = req('typescript');

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.startsWith('.') && context.parentURL) {
      const parentPath = fileURLToPath(context.parentURL);
      const baseDir = path.dirname(parentPath);
      for (const cand of [
        path.resolve(baseDir, specifier),
        path.resolve(baseDir, specifier.replace(/\.js$/, '.ts')),
        path.resolve(baseDir, specifier.replace(/\.mjs$/, '.ts')),
      ]) {
        if (fs.existsSync(cand)) {
          return { url: pathToFileURL(cand).href, shortCircuit: true };
        }
      }
    }
    if (
      !specifier.startsWith('.') &&
      !specifier.startsWith('/') &&
      !specifier.startsWith('node:') &&
      !specifier.startsWith('file:')
    ) {
      try {
        return nextResolve(specifier, context);
      } catch {
        return nextResolve(specifier, {
          ...context,
          parentURL: pathToFileURL(path.join(tcModules, 'typescript/package.json')).href,
        });
      }
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url.endsWith('.ts')) {
      const source = fs.readFileSync(fileURLToPath(url), 'utf8');
      const out = ts.transpileModule(source, {
        fileName: fileURLToPath(url),
        compilerOptions: {
          module: ts.ModuleKind.ESNext,
          target: ts.ScriptTarget.ES2022,
          moduleResolution: ts.ModuleResolutionKind.Bundler,
        },
      });
      return { format: 'module', source: out.outputText, shortCircuit: true };
    }
    return nextLoad(url, context);
  },
});

function walkSourceFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'target') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...walkSourceFiles(full));
    } else if (entry.name.endsWith('.ts') || entry.name.endsWith('.mjs')) {
      out.push(full);
    }
  }
  return out;
}

test('transpiles and syntax-checks all source files cleanly', () => {
  const files = walkSourceFiles(repoRoot);
  assert.ok(files.length > 0);
  for (const f of files) {
    const src = fs.readFileSync(f, 'utf8');
    const res = ts.transpileModule(src, {
      fileName: f,
      reportDiagnostics: true,
      compilerOptions: {
        module: ts.ModuleKind.ESNext,
        target: ts.ScriptTarget.ES2022,
      },
    });
    assert.equal(res.diagnostics?.length ?? 0, 0, `Diagnostics in ${f}`);
  }
});

test('imports entry module and passes functional smoke assertions', async () => {
  const entryUrl = pathToFileURL(path.join(repoRoot, "src/index.ts")).href;
  const pkg = await import(entryUrl);
  assert.ok(Object.keys(pkg).length > 0);
});

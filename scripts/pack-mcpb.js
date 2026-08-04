#!/usr/bin/env node

/**
 * Pack script for creating MCPB (MCP Bundle) distribution.
 * Creates a clean staging directory with only production deps,
 * then runs mcpb pack to create the bundle.
 */

import { execFileSync } from 'child_process';
import {
  cpSync,
  mkdirSync,
  rmSync,
  existsSync,
  copyFileSync,
  readFileSync,
  writeFileSync,
  statSync,
  readdirSync,
} from 'fs';
import { resolve, join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const ROOT = resolve(__dirname, '..');
const STAGING = resolve(ROOT, '.mcpb-staging');
const NPM_CLI = process.env.npm_execpath;

function run(file, args, opts = {}) {
  console.log(`> ${file} ${args.join(' ')}`);
  execFileSync(file, args, { stdio: 'inherit', ...opts });
}

function runNpm(args, opts = {}) {
  if (NPM_CLI) {
    run(process.execPath, [NPM_CLI, ...args], opts);
    return;
  }
  if (process.platform === 'win32') {
    throw new Error('Run pack:mcpb through npm so npm_execpath is available.');
  }
  run('npm', args, opts);
}

function captureNpm(args, opts = {}) {
  if (NPM_CLI) {
    return execFileSync(process.execPath, [NPM_CLI, ...args], opts);
  }
  if (process.platform === 'win32') {
    throw new Error('Run pack:mcpb through npm so npm_execpath is available.');
  }
  return execFileSync('npm', args, opts);
}

function removeFiles(root, shouldRemove) {
  if (!existsSync(root)) return;
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      removeFiles(path, shouldRemove);
    } else if (entry.isFile() && shouldRemove(entry.name)) {
      rmSync(path, { force: true });
    }
  }
}

const PRUNE_DIRECTORIES = new Set(['test', 'tests', '__tests__', 'examples', 'example']);
const PRUNE_FILE_PATTERNS = [
  /\.map$/i,
  /^CHANGELOG/i,
  /^HISTORY/i,
  /^CONTRIBUTING/i,
  /^\.eslintrc/i,
  /^\.prettierrc/i,
  /^tsconfig\.json$/i,
];

function pruneNodeModules(root) {
  if (!existsSync(root)) return;
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      if (PRUNE_DIRECTORIES.has(entry.name)) {
        rmSync(path, { recursive: true, force: true });
      } else {
        pruneNodeModules(path);
      }
    } else if (
      entry.isFile() &&
      PRUNE_FILE_PATTERNS.some((pattern) => pattern.test(entry.name))
    ) {
      rmSync(path, { force: true });
    }
  }
}

try {
  // 1. Build the project
  console.log('\n=== Building project ===');
  runNpm(['run', 'build'], { cwd: ROOT });

  // 2. Clean and create staging directory
  console.log('\n=== Preparing staging directory ===');
  if (existsSync(STAGING)) rmSync(STAGING, { recursive: true });
  mkdirSync(STAGING, { recursive: true });

  // 3. Copy production files (sync manifest version from package.json)
  console.log('\n=== Copying production files ===');
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  cpSync(join(ROOT, 'dist'), join(STAGING, 'dist'), { recursive: true });
  const manifest = JSON.parse(readFileSync(join(ROOT, 'manifest.json'), 'utf8'));
  manifest.version = pkg.version;
  writeFileSync(
    join(STAGING, 'manifest.json'),
    JSON.stringify(manifest, null, 2) + '\n'
  );
  copyFileSync(join(ROOT, 'README.md'), join(STAGING, 'README.md'));
  if (existsSync(join(ROOT, 'LICENSE'))) {
    copyFileSync(join(ROOT, 'LICENSE'), join(STAGING, 'LICENSE'));
  }

  // 4. Create a minimal package.json with only production deps
  const prodPkg = {
    name: pkg.name,
    version: pkg.version,
    description: pkg.description,
    main: pkg.main,
    dependencies: pkg.dependencies,
  };
  writeFileSync(
    join(STAGING, 'package.json'),
    JSON.stringify(prodPkg, null, 2)
  );

  // 5. Copy only production dependencies
  console.log('\n=== Copying production dependencies ===');
  const prodPaths = captureNpm(
    ['ls', '--production', '--parseable', '--all'],
    { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }
  )
    .split('\n')
    .filter(p => p.includes('node_modules'))
    .map(p => p.trim());
  console.log(`  ${prodPaths.length} production packages`);
  for (const absPath of prodPaths) {
    const relPath = absPath.slice(ROOT.length + 1);
    const destPath = join(STAGING, relPath);
    if (existsSync(absPath)) {
      mkdirSync(join(destPath, '..'), { recursive: true });
      cpSync(absPath, destPath, { recursive: true });
    }
  }

  // 6. Remove unnecessary files from staging
  removeFiles(join(STAGING, 'dist'), (name) => name.endsWith('.map'));
  pruneNodeModules(join(STAGING, 'node_modules'));

  // 7. Copy .mcpbignore if present
  if (existsSync(join(ROOT, '.mcpbignore'))) {
    copyFileSync(join(ROOT, '.mcpbignore'), join(STAGING, '.mcpbignore'));
  }

  // 8. Pack the bundle
  console.log('\n=== Packing MCPB bundle ===');
  const bundleName = pkg.name.replace(/^@.*\//, '');
  const bundlePath = join(ROOT, `${bundleName}.mcpb`);
  runNpm(['exec', '--', 'mcpb', 'pack', STAGING, bundlePath], { cwd: ROOT });

  // 9. Cleanup
  console.log('\n=== Cleanup ===');
  rmSync(STAGING, { recursive: true });

  console.log('\n=== Done! ===');
  if (existsSync(bundlePath)) {
    const stats = statSync(bundlePath);
    console.log(`Bundle: ${bundleName}.mcpb (${(stats.size / 1024 / 1024).toFixed(1)}MB)`);
  }
} catch (error) {
  console.error('Pack failed:', error.message);
  if (existsSync(STAGING)) rmSync(STAGING, { recursive: true });
  process.exit(1);
}

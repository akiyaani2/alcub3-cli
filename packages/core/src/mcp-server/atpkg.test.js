import { test, expect, beforeAll } from 'vitest';
import fs from 'fs/promises';
import path from 'path';
import { createAtpkg, validateAtpkg } from '../mcp/atpkg.js';
import { sign, generateKeyPair } from '../crypto.js';

let keys;

beforeAll(async () => {
  keys = await generateKeyPair();
});

test('create and validate a valid .atpkg file', async () => {
  const contextData = { 'conversation': 'hello' };
  const files = [
    { name: 'test.txt', content: 'This is a test file.' },
  ];

  const atpkgPath = await createAtpkg(contextData, files, keys.privateKey);

  expect(await fs.access(atpkgPath).then(() => true).catch(() => false)).toBe(true);

  const { isValid, manifest } = await validateAtpkg(atpkgPath, keys.publicKey);

  expect(isValid).toBe(true);
  expect(manifest.version).toBe('1.0');
  expect(manifest.files[0].name).toBe('test.txt');

  await fs.unlink(atpkgPath);
});

test('fail validation for a tampered .atpkg file', async () => {
  const contextData = { 'conversation': 'hello' };
  const files = [
    { name: 'test.txt', content: 'This is a test file.' },
  ];

  const atpkgPath = await createAtpkg(contextData, files, keys.privateKey);

  // Tamper with the package
  await fs.appendFile(atpkgPath, 'tampered');

  const { isValid } = await validateAtpkg(atpkgPath, keys.publicKey);

  expect(isValid).toBe(false);

  await fs.unlink(atpkgPath);
});

test('fail validation for a package with a bad signature', async () => {
    const contextData = { 'conversation': 'hello' };
    const files = [
      { name: 'test.txt', content: 'This is a test file.' },
    ];
  
    const atpkgPath = await createAtpkg(contextData, files, keys.privateKey);
  
    const otherKeys = await generateKeyPair();

    const { isValid } = await validateAtpkg(atpkgPath, otherKeys.publicKey);
  
    expect(isValid).toBe(false);
  
    await fs.unlink(atpkgPath);
  });
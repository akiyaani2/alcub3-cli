import { promises as fs } from 'fs';
import path from 'path';
import os from 'os';
import { sign, verify } from '../crypto.js';
import { randomUUID } from 'crypto';

const PACKAGE_VERSION = '1.0';

export const createAtpkg = async (contextData, files, privateKeyPem) => {
  const manifest = {
    version: PACKAGE_VERSION,
    files: files.map(f => ({ name: f.name, size: f.content.length })),
    timestamp: Date.now(),
  };

  const payload = { manifest, contextData, files };
  const payloadString = JSON.stringify(payload);
  const signature = await sign(payloadString, privateKeyPem);

  const finalPackage = { payload, signature };

  const filePath = path.join(os.tmpdir(), `alcub3-${randomUUID()}.atpkg.zip`);
  await fs.writeFile(filePath, JSON.stringify(finalPackage), 'utf8');
  return filePath;
};

export const validateAtpkg = async (atpkgPath, publicKeyPem) => {
  try {
    const data = await fs.readFile(atpkgPath, 'utf8');
    const parsed = JSON.parse(data);
    if (!parsed.payload || !parsed.signature) {
      return { isValid: false, manifest: null };
    }
    const isValid = verify(JSON.stringify(parsed.payload), parsed.signature, publicKeyPem);
    return { isValid, manifest: parsed.payload.manifest };
  } catch {
    return { isValid: false, manifest: null };
  }
};

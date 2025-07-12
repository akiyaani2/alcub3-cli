import { describe, it, expect } from 'vitest';

import { SpotSecurityContext } from './spot-security-adapter.js';
import { SecurityClassification } from '../../interfaces/robotics-types.js';

// Basic unit tests ensuring core cryptographic helpers behave as expected.

describe('SpotSecurityContext', () => {
  it('encrypts and decrypts data symmetrically', () => {
    const ctx = new SpotSecurityContext(SecurityClassification.SECRET);
    const sample = { message: 'hello', value: 42 };

    const encrypted = ctx.encrypt(sample);
    expect(typeof encrypted).toBe('string');
    expect(encrypted).not.toContain('hello'); // ciphertext should hide plaintext

    const decrypted = ctx.decrypt(encrypted);
    expect(decrypted).toEqual(sample);
  });

  it('signs and verifies data integrity correctly', () => {
    const ctx = new SpotSecurityContext(SecurityClassification.SECRET);
    const payload = { message: 'integrity' };

    const signature = ctx.sign(payload);
    expect(ctx.verify(payload, signature)).toBe(true);

    // Tamper with the payload to ensure verification fails
    const tampered = { ...payload, extra: 'tamper' };
    expect(ctx.verify(tampered, signature)).toBe(false);
  });
}); 
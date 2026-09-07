import { describe, it, expect } from 'vitest';
import {
  SECRET_PATTERNS,
  calculateEntropy,
  isFalsePositive,
  createPreview,
} from '../utils/patterns';

describe('Pattern Detection & Secret Scanning', () => {
  describe('SECRET_PATTERNS matching', () => {
    it('detects AWS Access Keys', () => {
      const awsPattern = SECRET_PATTERNS.find(p => p.type === 'AWS_ACCESS_KEY');
      expect(awsPattern).toBeDefined();

      const validAwsKey = 'AKIAIOSFODNN7EXAMPLE';
      const regex = new RegExp(awsPattern!.pattern.source, awsPattern!.pattern.flags);
      expect(regex.test(validAwsKey)).toBe(true);

      const invalidKey = 'NOT_AN_AWS_KEY';
      regex.lastIndex = 0;
      expect(regex.test(invalidKey)).toBe(false);
    });

    it('detects GitHub Personal Access Tokens', () => {
      const githubPattern = SECRET_PATTERNS.find(p => p.type === 'GITHUB_TOKEN');
      expect(githubPattern).toBeDefined();

      const validGhToken = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';
      const regex = new RegExp(githubPattern!.pattern.source, githubPattern!.pattern.flags);
      expect(regex.test(validGhToken)).toBe(true);

      const invalidToken = 'ghp_short';
      regex.lastIndex = 0;
      expect(regex.test(invalidToken)).toBe(false);
    });

    it('detects Database Connection Strings', () => {
      const dbPattern = SECRET_PATTERNS.find(p => p.type === 'DATABASE_URL');
      expect(dbPattern).toBeDefined();

      const dbUrl = 'postgresql://admin:superSecret123@db.internal:5432/production_db';
      const regex = new RegExp(dbPattern!.pattern.source, dbPattern!.pattern.flags);
      expect(regex.test(dbUrl)).toBe(true);
    });

    it('detects Private Keys', () => {
      const pkPattern = SECRET_PATTERNS.find(p => p.type === 'PRIVATE_KEY');
      expect(pkPattern).toBeDefined();

      const rsaKey = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----';
      const regex = new RegExp(pkPattern!.pattern.source, pkPattern!.pattern.flags);
      expect(regex.test(rsaKey)).toBe(true);
    });
  });

  describe('Entropy Calculation', () => {
    it('computes higher entropy for random alphanumeric strings than repetitive ones', () => {
      const repetitive = 'aaaaaaaaaaaaaaaaaaaaaaaa';
      const repetitiveEntropy = calculateEntropy(repetitive);

      const highEntropy = '8fK#9zL@2pQ!7xR$4mN&1wE*';
      const highEntropyVal = calculateEntropy(highEntropy);

      expect(repetitiveEntropy).toBe(0);
      expect(highEntropyVal).toBeGreaterThan(3.5);
    });

    it('returns 0 for empty string', () => {
      expect(calculateEntropy('')).toBe(0);
    });
  });

  describe('False Positive Suppression', () => {
    it('suppresses placeholder and example values', () => {
      expect(isFalsePositive('example', 'API_KEY = example')).toBe(true);
      expect(isFalsePositive('your_key_here', 'AWS_KEY=your_key_here')).toBe(true);
      expect(isFalsePositive('changeme', 'PASSWORD=changeme')).toBe(true);
      expect(isFalsePositive('dummy', 'dummy string')).toBe(true);
      expect(isFalsePositive('sample', 'sample token')).toBe(true);
    });

    it('suppresses matches containing asterisks or multiple dots', () => {
      expect(isFalsePositive('secret_******_end', 'some context')).toBe(true);
      expect(isFalsePositive('secret......token', 'some context')).toBe(true);
    });

    it('identifies false positive context markers', () => {
      expect(isFalsePositive('randomSecretToken9123847', 'This is a placeholder for future')).toBe(true);
      expect(isFalsePositive('randomSecretToken9123847', 'visit example.com for documentation')).toBe(true);
    });

    it('does NOT suppress authentic high-entropy secret in normal context', () => {
      const realSecret = 'ghp_abc1234567890defghijklmnopqrstuv';
      const context = 'const token = process.env.GH_TOKEN || "ghp_abc1234567890defghijklmnopqrstuv";';
      expect(isFalsePositive(realSecret, context)).toBe(false);
    });
  });

  describe('createPreview obfuscation', () => {
    it('masks the middle of short strings', () => {
      const preview = createPreview('1234567890');
      expect(preview).toBe('1234***7890');
    });

    it('masks long strings with ellipsis', () => {
      const preview = createPreview('abcdefghijklmnopqrstuvwxyz0123456789');
      expect(preview.startsWith('abcdefghij...')).toBe(true);
      expect(preview.endsWith('0123456789')).toBe(true);
    });
  });
});

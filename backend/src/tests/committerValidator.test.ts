import { describe, it, expect } from 'vitest';
import {
  cleanCommitterEmail,
  isValidCommitterEmail,
} from '../utils/committerValidator';

describe('Committer Email Validator', () => {
  describe('cleanCommitterEmail', () => {
    it('strips angle brackets, quotes, and whitespace and normalizes to lowercase', () => {
      expect(cleanCommitterEmail('<John.Doe@Example.org>')).toBe('john.doe@example.org');
      expect(cleanCommitterEmail('  "alice@corp.io"  ')).toBe('alice@corp.io');
      expect(cleanCommitterEmail("'bob@company.com'")).toBe('bob@company.com');
    });

    it('returns null for empty or invalid inputs', () => {
      expect(cleanCommitterEmail(null)).toBeNull();
      expect(cleanCommitterEmail(undefined)).toBeNull();
      expect(cleanCommitterEmail('')).toBeNull();
      expect(cleanCommitterEmail('   ')).toBeNull();
    });
  });

  describe('isValidCommitterEmail', () => {
    it('accepts legitimate committer emails', () => {
      expect(isValidCommitterEmail('gildas@breizh.org')).toBe(true);
      expect(isValidCommitterEmail('developer@mycompany.co.uk')).toBe(true);
      expect(isValidCommitterEmail('jane.doe+dev@service.cloud')).toBe(true);
    });

    it('rejects GitHub noreply masks', () => {
      expect(isValidCommitterEmail('12345678+username@users.noreply.github.com')).toBe(false);
      expect(isValidCommitterEmail('username@users.noreply.github.com')).toBe(false);
      expect(isValidCommitterEmail('noreply@github.com')).toBe(false);
    });

    it('rejects bots and automated accounts', () => {
      expect(isValidCommitterEmail('dependabot[bot]@users.noreply.github.com')).toBe(false);
      expect(isValidCommitterEmail('bot-worker@automation.com')).toBe(false);
      expect(isValidCommitterEmail('ci-bot@company.org')).toBe(false);
    });

    it('rejects dummy, test, and placeholder domains', () => {
      expect(isValidCommitterEmail('user@localhost')).toBe(false);
      expect(isValidCommitterEmail('admin@localdomain')).toBe(false);
      expect(isValidCommitterEmail('test@example.com')).toBe(false);
      expect(isValidCommitterEmail('dev@sample.net')).toBe(false);
      expect(isValidCommitterEmail('user@invalid.org')).toBe(false);
      expect(isValidCommitterEmail('someone@mailinator.com')).toBe(false);
    });

    it('rejects placeholder local parts', () => {
      expect(isValidCommitterEmail('noreply@domain.com')).toBe(false);
      expect(isValidCommitterEmail('no-reply@domain.com')).toBe(false);
      expect(isValidCommitterEmail('anonymous@domain.com')).toBe(false);
      expect(isValidCommitterEmail('placeholder@domain.com')).toBe(false);
      expect(isValidCommitterEmail('null@domain.com')).toBe(false);
      expect(isValidCommitterEmail('undefined@domain.com')).toBe(false);
    });
  });
});

import { describe, it, expect } from 'vitest';
import {
  calculateCriticalityScore,
  scoreToCriticality,
  calculateFileCriticalityScore,
  TYPE_WEIGHTS,
} from '../services/scoring.service';

describe('Scoring Service', () => {
  describe('calculateCriticalityScore', () => {
    it('scores critical secrets (e.g. AWS Secret Key, Private Key) higher than basic ones', () => {
      const highValueScore = calculateCriticalityScore({
        type: 'AWS_SECRET_KEY',
        content: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        context: 'export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        commitDate: new Date(),
      });

      const emailScore = calculateCriticalityScore({
        type: 'EMAIL',
        content: 'test@example.com',
        context: 'Contact author at test@example.com',
        commitDate: new Date(),
      });

      expect(highValueScore).toBeGreaterThan(emailScore);
      expect(highValueScore).toBeGreaterThanOrEqual(75);
    });

    it('awards context bonus for keywords like production or prod', () => {
      const prodContextScore = calculateCriticalityScore({
        type: 'DATABASE_URL',
        content: 'postgres://root:pass@prod-db.internal:5432/main',
        context: 'production database credentials for live deployment',
      });

      const genericContextScore = calculateCriticalityScore({
        type: 'DATABASE_URL',
        content: 'postgres://root:pass@prod-db.internal:5432/main',
        context: 'local connection configuration',
      });

      expect(prodContextScore).toBeGreaterThan(genericContextScore);
    });

    it('keeps score within 0 to 100 range', () => {
      const score = calculateCriticalityScore({
        type: '1PASSWORD_SECRET_KEY',
        content: 'super-critical-secret-content-1234567890',
        context: 'export PROD_MASTER_KEY=production credential api key secret',
        commitDate: new Date(),
      });

      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(100);
    });
  });

  describe('scoreToCriticality', () => {
    it('correctly maps numeric scores to severity brackets', () => {
      expect(scoreToCriticality(95)).toBe('CRITICAL');
      expect(scoreToCriticality(90)).toBe('CRITICAL');
      expect(scoreToCriticality(85)).toBe('HIGH');
      expect(scoreToCriticality(75)).toBe('HIGH');
      expect(scoreToCriticality(60)).toBe('MEDIUM');
      expect(scoreToCriticality(50)).toBe('MEDIUM');
      expect(scoreToCriticality(35)).toBe('LOW');
      expect(scoreToCriticality(25)).toBe('LOW');
      expect(scoreToCriticality(15)).toBe('INFO');
      expect(scoreToCriticality(0)).toBe('INFO');
    });
  });

  describe('calculateFileCriticalityScore', () => {
    it('returns highest individual score with type density bonus', () => {
      const secrets = [
        { type: 'AWS_ACCESS_KEY', score: 80, criticality: 'HIGH' },
        { type: 'AWS_SECRET_KEY', score: 92, criticality: 'CRITICAL' },
      ];

      const result = calculateFileCriticalityScore(secrets);
      expect(result.score).toBeGreaterThanOrEqual(92);
      expect(result.primaryType).toBe('AWS_SECRET_KEY');
      expect(result.criticality).toBe('CRITICAL');
    });

    it('handles single secret', () => {
      const secrets = [{ type: 'EMAIL', score: 20, criticality: 'INFO' }];
      const result = calculateFileCriticalityScore(secrets);

      expect(result.score).toBe(20);
      expect(result.primaryType).toBe('EMAIL');
      expect(result.criticality).toBe('INFO');
    });
  });
});

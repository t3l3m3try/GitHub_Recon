import { describe, it, expect } from 'vitest';
import { scopeFor } from '../middleware/auth.middleware';
import { Request } from 'express';

describe('Multi-tenant Auth Scoping (scopeFor)', () => {
  it('returns unscoped where clauses for superadmin without orgId query', () => {
    const mockReq = {
      user: {
        id: 'super-1',
        isSuperAdmin: true,
        role: 'SUPERADMIN',
        orgId: null,
      },
      query: {},
    } as unknown as Request;

    const scope = scopeFor(mockReq);

    expect(scope.unscoped).toBe(true);
    expect(scope.orgId).toBeNull();
    expect(scope.domain).toEqual({});
    expect(scope.scan).toEqual({});
    expect(scope.finding).toEqual({});
  });

  it('allows superadmin to filter specifically by orgId via query param', () => {
    const mockReq = {
      user: {
        id: 'super-1',
        isSuperAdmin: true,
        role: 'SUPERADMIN',
        orgId: null,
      },
      query: { orgId: 'tenant-42' },
    } as unknown as Request;

    const scope = scopeFor(mockReq);

    expect(scope.unscoped).toBe(false);
    expect(scope.orgId).toBe('tenant-42');
    expect(scope.domain).toEqual({ orgId: 'tenant-42' });
    expect(scope.scan).toEqual({ domain: { orgId: 'tenant-42' } });
    expect(scope.finding).toEqual({ scan: { domain: { orgId: 'tenant-42' } } });
  });

  it('pins regular organization user to their own orgId and ignores query params', () => {
    const mockReq = {
      user: {
        id: 'user-1',
        isSuperAdmin: false,
        role: 'MEMBER',
        orgId: 'tenant-acme',
      },
      query: { orgId: 'malicious-attempt-to-view-other-org' },
    } as unknown as Request;

    const scope = scopeFor(mockReq);

    expect(scope.unscoped).toBe(false);
    expect(scope.orgId).toBe('tenant-acme');
    expect(scope.domain).toEqual({ orgId: 'tenant-acme' });
    expect(scope.scan).toEqual({ domain: { orgId: 'tenant-acme' } });
    expect(scope.finding).toEqual({ scan: { domain: { orgId: 'tenant-acme' } } });
  });

  it('completely isolates user without an assigned organization', () => {
    const mockReq = {
      user: {
        id: 'orphan-1',
        isSuperAdmin: false,
        role: 'MEMBER',
        orgId: null,
      },
      query: {},
    } as unknown as Request;

    const scope = scopeFor(mockReq);

    expect(scope.unscoped).toBe(false);
    expect(scope.orgId).toBeNull();
    expect(scope.domain).toEqual({ orgId: '__no_org__' });
    expect(scope.scan).toEqual({ domain: { orgId: '__no_org__' } });
  });
});

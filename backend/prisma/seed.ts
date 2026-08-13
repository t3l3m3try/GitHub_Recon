import { PrismaClient } from '@prisma/client';
import {
  generateStrongPassword,
  hashPassword,
  validatePasswordStrength,
} from '../src/services/auth.service';
import { ROLES } from '../src/utils/permissions';

const prisma = new PrismaClient();

/**
 * Seed
 *
 * Ensures the system has a super administrator, so a fresh install is usable
 * without any account being auto-provisioned at runtime. Optionally creates
 * organizations named in SEED_ORGANIZATIONS, and adopts any domain that has no
 * organization (which happens when upgrading from a single-tenant install).
 *
 * Idempotent: existing accounts and organizations are never overwritten, and a
 * password is printed only for an account created by this run. Generated
 * passwords are shown once and stored only as bcrypt hashes.
 */

/**
 * Optional organizations to create on first run, as a comma-separated list:
 *   SEED_ORGANIZATIONS="Acme Corp,Globex"
 * Leave unset to start with none and create them from the Admin console instead.
 */
const SEED_ORGANIZATIONS = (process.env.SEED_ORGANIZATIONS || '')
  .split(',')
  .map(name => name.trim())
  .filter(Boolean);

/** Organization that adopts any domain left without one (upgrades from a pre-tenant install). */
const DEFAULT_ORG_NAME = process.env.DEFAULT_ORGANIZATION || 'Default Organization';

const SUPER_ADMIN_EMAIL = process.env.SUPER_ADMIN_EMAIL || 'superadmin@localhost.local';
const SUPER_ADMIN_USERNAME = process.env.SUPER_ADMIN_USERNAME || 'superadmin';

interface Credential {
  label: string;
  username: string;
  email: string;
  password: string;
  role: string;
  org: string;
}

async function main() {
  console.log('\n🌱 Seeding access control...\n');

  const created: Credential[] = [];

  // ── Super administrator ──────────────────────────────────────────────────
  let superAdmin = await prisma.user.findFirst({ where: { role: ROLES.SUPER_ADMIN } });

  if (superAdmin) {
    console.log(`   ✔ Super admin already exists: ${superAdmin.email} (password unchanged)`);
  } else {
    // Allow an operator-supplied password, otherwise generate a strong one.
    let password = process.env.SUPER_ADMIN_PASSWORD || '';
    if (password) {
      const check = validatePasswordStrength(password, SUPER_ADMIN_USERNAME, SUPER_ADMIN_EMAIL);
      if (!check.valid) {
        throw new Error(`SUPER_ADMIN_PASSWORD does not meet the policy:\n  - ${check.errors.join('\n  - ')}`);
      }
    } else {
      password = generateStrongPassword(24);
    }

    superAdmin = await prisma.user.create({
      data: {
        email: SUPER_ADMIN_EMAIL,
        username: SUPER_ADMIN_USERNAME,
        passwordHash: await hashPassword(password),
        role: ROLES.SUPER_ADMIN,
        orgId: null,
        active: true,
        // The password is known to whoever runs the seed, so it must be changed
        // at first login before the account can be used for anything else.
        mustChangePassword: true,
      },
    });

    created.push({
      label: 'SUPER ADMIN',
      username: superAdmin.username,
      email: superAdmin.email,
      password,
      role: superAdmin.role,
      org: '—',
    });
    console.log(`   ✚ Super admin created: ${superAdmin.email}`);
  }

  const slugify = (name: string) =>
    name.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);

  /** Create an organization if it is not already present. */
  async function ensureOrganization(name: string) {
    const slug = slugify(name);
    const existing = await prisma.organization.findFirst({
      where: { OR: [{ name }, { slug }] },
    });
    if (existing) {
      console.log(`   ✔ Organization already exists: ${existing.name}`);
      return existing;
    }
    const org = await prisma.organization.create({ data: { name, slug } });
    console.log(`   ✚ Organization created: ${org.name}`);
    return org;
  }

  // ── Optional organizations from configuration ────────────────────────────
  for (const name of SEED_ORGANIZATIONS) {
    await ensureOrganization(name);
  }

  // ── Adopt any domain that has no organization ────────────────────────────
  // Upgrading from a single-tenant install leaves domains unassigned; without an
  // organization they would be invisible to everyone but the super admin.
  const orphanDomains = await prisma.domain.findMany({ where: { orgId: null } });
  if (orphanDomains.length > 0) {
    const fallbackOrg = await ensureOrganization(DEFAULT_ORG_NAME);
    for (const domain of orphanDomains) {
      await prisma.domain.update({
        where: { id: domain.id },
        data: { orgId: fallbackOrg.id, userId: superAdmin!.id },
      });
      const scans = await prisma.scan.count({ where: { domainId: domain.id } });
      const findings = await prisma.finding.count({ where: { scan: { domainId: domain.id } } });
      console.log(`   ↳ Adopted an unassigned domain → ${fallbackOrg.name} (${scans} scan(s), ${findings} finding(s))`);
    }
  }

  // ── Retire the legacy synthetic dev account ──────────────────────────────
  const legacy = await prisma.user.findFirst({ where: { username: 'legacy-dev' } });
  if (legacy) {
    const fallback = superAdmin!;
    // Re-point anything still owned by it BEFORE deleting, because Domain and
    // Scan cascade from User and would otherwise take the findings with them.
    const domains = await prisma.domain.updateMany({ where: { userId: legacy.id }, data: { userId: fallback.id } });
    const scans = await prisma.scan.updateMany({ where: { userId: legacy.id }, data: { userId: fallback.id } });
    await prisma.session.deleteMany({ where: { userId: legacy.id } });
    await prisma.querySetting.deleteMany({ where: { userId: legacy.id } });
    await prisma.user.delete({ where: { id: legacy.id } });
    console.log(`   ✚ Removed legacy dev account (reassigned ${domains.count} domain(s), ${scans.count} scan(s))`);
  }

  // ── Report ───────────────────────────────────────────────────────────────
  const [orgCount, userCount, domainCount, unassigned] = await Promise.all([
    prisma.organization.count(),
    prisma.user.count(),
    prisma.domain.count(),
    prisma.domain.count({ where: { orgId: null } }),
  ]);

  console.log(`\n   Summary: ${orgCount} organization(s), ${userCount} user(s), ${domainCount} domain(s)`);
  if (unassigned > 0) {
    console.log(`   ⚠️  ${unassigned} domain(s) are not assigned to any organization — assign them from the Admin console.`);
  }

  if (created.length > 0) {
    console.log('\n' + '='.repeat(78));
    console.log('  CREDENTIALS — shown once. Copy them now, then change them at first login.');
    console.log('='.repeat(78));
    for (const c of created) {
      console.log(`\n  ${c.label}   [${c.role}]${c.org !== '—' ? `  organization: ${c.org}` : ''}`);
      console.log(`    username : ${c.username}`);
      console.log(`    email    : ${c.email}`);
      console.log(`    password : ${c.password}`);
    }
    console.log('\n' + '='.repeat(78));
    console.log('  Every account above must change its password at first login.');
    console.log('  Passwords are stored only as bcrypt hashes and cannot be recovered —');
    console.log('  use the Admin console to reset one if it is lost.');
    console.log('='.repeat(78) + '\n');
  } else {
    console.log('\n   No new accounts created; no credentials to display.\n');
  }

  console.log('✅ Seeding completed\n');
}

main()
  .catch((e) => {
    console.error('❌ Seeding failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

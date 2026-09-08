import { PrismaClient } from '@prisma/client';
import {
  hashPassword,
  validatePasswordStrength,
} from '../src/services/auth.service';
import { ROLES } from '../src/utils/permissions';

const prisma = new PrismaClient();

async function main() {
  const args = process.argv.slice(2);
  const mode = args[0];

  console.log('\n🔧 Super Admin Password Utility\n');

  let superAdmin = await prisma.user.findFirst({ where: { role: ROLES.SUPER_ADMIN } });
  if (!superAdmin) {
    console.error('❌ No super administrator account found in the database. Run `npm run db:seed` first.');
    process.exit(1);
  }

  if (mode === '--setup' || mode === '-s') {
    // Reset to setup wizard mode
    await prisma.user.update({
      where: { id: superAdmin.id },
      data: {
        passwordSet: false,
        mustChangePassword: false,
        failedLoginAttempts: 0,
        lockedUntil: null,
      },
    });
    console.log('✅ Super admin has been reset to Setup Wizard mode.');
    console.log('👉 Open http://localhost:5173/ in your browser to complete the initial setup.\n');
    return;
  }

  const newPassword = args[0];
  if (!newPassword) {
    console.log('Usage:');
    console.log('  npm run db:reset-admin <newPassword>   # Set a specific password');
    console.log('  npm run db:reset-admin --setup        # Re-open the initial web setup screen');
    console.log('\nExample:');
    console.log('  npm run db:reset-admin "MySecret1234!"\n');
    process.exit(1);
  }

  const check = validatePasswordStrength(newPassword, superAdmin.username, superAdmin.email);
  if (!check.valid) {
    console.error('❌ Password does not satisfy policy requirements:');
    check.errors.forEach(err => console.error(`   - ${err}`));
    console.error('\nRequirements: at least 12 chars, uppercase, lowercase, digit, symbol.\n');
    process.exit(1);
  }

  await prisma.user.update({
    where: { id: superAdmin.id },
    data: {
      passwordHash: await hashPassword(newPassword),
      passwordSet: true,
      mustChangePassword: false,
      failedLoginAttempts: 0,
      lockedUntil: null,
      active: true,
    },
  });

  console.log('✅ Super admin password successfully reset!');
  console.log(`   Username: ${superAdmin.username}`);
  console.log(`   Email:    ${superAdmin.email}`);
  console.log(`   Status:   Unlocked & active`);
  console.log('\n👉 You can now log in at http://localhost:5173/\n');
}

main()
  .catch((err) => {
    console.error('Error:', err);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());

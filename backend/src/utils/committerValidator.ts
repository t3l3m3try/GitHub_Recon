/**
 * Committer Email Validator
 * Validates whether an extracted committer/author email is an authentic, valid email
 * and discards bot masks, dummy domains, localhost, and placeholders.
 */

// Standard RFC 5322 compatible regex for general email structure
const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;

// Domains that should be discarded (bots, privacy masks, dummies, local domains)
const BLOCKED_DOMAIN_PATTERNS: RegExp[] = [
  /users\.noreply\.github\.com$/i,
  /^noreply\.github\.com$/i,
  /^github\.com$/i,
  /localhost$/i,
  /localdomain$/i,
  /\.local$/i,
  /\.internal$/i,
  /\.lan$/i,
  /^example\.(com|org|net)$/i,
  /^test\.(com|org|net)$/i,
  /^sample\.(com|org|net)$/i,
  /^invalid\.(com|org|net)$/i,
  /^none\.(com|org|net)$/i,
  /^mailinator\.com$/i,
];

// Local parts (before @) that indicate a placeholder or non-human identity
const BLOCKED_LOCAL_PARTS = new Set([
  'noreply',
  'no-reply',
  'root',
  'none',
  'null',
  'undefined',
  'test',
  'admin',
  'your-email',
  'youremail',
  'email',
  'name',
  'user',
  'author',
  'committer',
  'anonymous',
  'nobody',
  'placeholder'
]);

/**
 * Clean and normalize email string
 */
export function cleanCommitterEmail(email: string | null | undefined): string | null {
  if (!email || typeof email !== 'string') return null;
  // Remove enclosing brackets, quotes, extra whitespace
  const cleaned = email.trim().replace(/^<|>$/g, '').replace(/^['"]|['"]$/g, '').toLowerCase().trim();
  return cleaned || null;
}

/**
 * Returns true if the email is structurally valid and represents an authentic committer email.
 * Discards GitHub privacy masks, bots, placeholders, and dummy addresses.
 */
export function isValidCommitterEmail(rawEmail: string | null | undefined): boolean {
  const email = cleanCommitterEmail(rawEmail);
  if (!email) return false;

  // Length sanity check (RFC 5321 limits total length to 254 characters)
  if (email.length < 5 || email.length > 254) return false;

  // Regex format validation
  if (!EMAIL_REGEX.test(email)) return false;

  const parts = email.split('@');
  if (parts.length !== 2) return false;

  const [localPart, domainPart] = parts;
  if (!localPart || !domainPart) return false;

  // Discard known bot local parts like 'dependabot[bot]', 'github-actions[bot]'
  if (localPart.includes('[bot]') || localPart.startsWith('bot-') || localPart.endsWith('-bot')) {
    return false;
  }

  // Discard numeric prefixes used in GitHub noreply (e.g. 49699333+username)
  if (/^\d+\+[a-zA-Z0-9._%-]+$/.test(localPart) && domainPart.toLowerCase().includes('github')) {
    return false;
  }

  // Discard blocked placeholder local parts
  if (BLOCKED_LOCAL_PARTS.has(localPart)) {
    return false;
  }

  // Discard blocked domains (privacy masks, dummy domains, localhost)
  for (const pattern of BLOCKED_DOMAIN_PATTERNS) {
    if (pattern.test(domainPart)) {
      return false;
    }
  }

  // Ensure TLD has at least 2 alpha characters
  const tld = domainPart.split('.').pop();
  if (!tld || tld.length < 2 || !/^[a-zA-Z]+$/.test(tld)) {
    return false;
  }

  return true;
}

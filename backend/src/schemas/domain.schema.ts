import { z } from 'zod';

const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

export const createDomainSchema = z.object({
  name: z
    .string({ required_error: 'Domain name is required' })
    .min(1, 'Domain name is required')
    .regex(domainRegex, 'Invalid domain format. Please use format like: example.com'),
  scanFrequency: z
    .enum(['manual', 'hourly', 'daily', 'weekly', 'monthly'])
    .optional()
    .default('manual'),
  orgId: z.string().optional(),
});

export const updateDomainSchema = z.object({
  name: z
    .string()
    .min(1, 'Domain name cannot be empty')
    .regex(domainRegex, 'Invalid domain format. Please use format like: example.com')
    .optional(),
  scanFrequency: z
    .enum(['manual', 'hourly', 'daily', 'weekly', 'monthly'])
    .optional(),
  active: z.boolean().optional(),
});

export type CreateDomainInput = z.infer<typeof createDomainSchema>;
export type UpdateDomainInput = z.infer<typeof updateDomainSchema>;

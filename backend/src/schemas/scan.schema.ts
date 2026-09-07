import { z } from 'zod';

export const createScanSchema = z.object({
  domainId: z
    .string({ required_error: 'Domain ID is required' })
    .min(1, 'Domain ID is required'),
});

export const getScanFindingsQuerySchema = z.object({
  page: z.string().optional().transform(v => (v ? Math.max(1, parseInt(v, 10) || 1) : 1)),
  limit: z.string().optional().transform(v => (v ? Math.min(200, Math.max(1, parseInt(v, 10) || 50)) : 50)),
  criticality: z.string().optional(),
  type: z.string().optional(),
  verified: z.enum(['true', 'false']).optional(),
  falsePositive: z.enum(['true', 'false']).optional(),
});

export type CreateScanInput = z.infer<typeof createScanSchema>;

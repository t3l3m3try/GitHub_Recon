import { z } from 'zod';

export const loginSchema = z
  .object({
    identifier: z.string().optional(),
    email: z.string().optional(),
    username: z.string().optional(),
    password: z.string({ required_error: 'Password is required' }).min(1, 'Password is required'),
  })
  .refine(
    data => Boolean(data.identifier || data.email || data.username),
    {
      message: 'Username/email is required',
      path: ['identifier'],
    }
  );

export const changePasswordSchema = z.object({
  currentPassword: z
    .string({ required_error: 'Current password is required' })
    .min(1, 'Current password is required'),
  newPassword: z
    .string({ required_error: 'New password is required' })
    .min(1, 'New password is required'),
});

export const verifyTwoFactorSchema = z.object({
  challengeToken: z
    .string({ required_error: 'Challenge token is required' })
    .min(1, 'A challenge token and code are required'),
  code: z
    .string({ required_error: 'Code is required' })
    .min(1, 'A challenge token and code are required'),
});

export type LoginInput = z.infer<typeof loginSchema>;
export type ChangePasswordInput = z.infer<typeof changePasswordSchema>;
export type VerifyTwoFactorInput = z.infer<typeof verifyTwoFactorSchema>;

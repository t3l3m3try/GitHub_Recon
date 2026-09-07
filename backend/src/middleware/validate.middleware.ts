import { Request, Response, NextFunction } from 'express';
import { ZodSchema, ZodError } from 'zod';

/**
 * Middleware factory for validating incoming request bodies against a Zod schema.
 */
export function validateBody(schema: ZodSchema) {
  return (req: Request, res: Response, next: NextFunction) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      const formattedErrors = result.error.errors.map(err => ({
        field: err.path.join('.') || 'body',
        message: err.message,
      }));
      return res.status(400).json({
        error: formattedErrors[0]?.message || 'Validation failed',
        details: formattedErrors,
      });
    }
    req.body = result.data;
    next();
  };
}

/**
 * Middleware factory for validating incoming query parameters against a Zod schema.
 */
export function validateQuery(schema: ZodSchema) {
  return (req: Request, res: Response, next: NextFunction) => {
    const result = schema.safeParse(req.query);
    if (!result.success) {
      const formattedErrors = result.error.errors.map(err => ({
        field: err.path.join('.') || 'query',
        message: err.message,
      }));
      return res.status(400).json({
        error: formattedErrors[0]?.message || 'Invalid query parameters',
        details: formattedErrors,
      });
    }
    req.query = result.data as any;
    next();
  };
}

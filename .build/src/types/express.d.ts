import { Request } from 'express';

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        role: string;
        clearance: string;
      };
      apiKeyData?: {
        keyId: string;
        classification: string;
      };
      authTime?: number;
      securityValidation?: any; // Replace 'any' with a more specific type if available
    }
  }
}

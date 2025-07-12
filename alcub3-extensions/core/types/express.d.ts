import { ClassificationLevel } from '../api/classification.js';

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        username: string;
        classification: ClassificationLevel;
        roles: string[];
        role?: string; // For backward compatibility
        clearance?: string; // For backward compatibility
      };
    }
  }
}

export {};
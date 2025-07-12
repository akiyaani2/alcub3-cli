import { describe, it, expect, beforeEach, vi } from 'vitest';
import { PerformanceBudget, BUDGETS } from './performance-budget.js';

describe('PerformanceBudget', () => {
  beforeEach(() => {
    PerformanceBudget.reset();
    vi.clearAllMocks();
  });

  it('should measure synchronous operations', () => {
    const result = PerformanceBudget.measure('file-operation', () => {
      // Simulate fast operation
      return 'test-result';
    });
    
    expect(result).toBe('test-result');
  });

  it('should measure async operations', async () => {
    const result = await PerformanceBudget.measureAsync('api-response', async () => {
      // Simulate fast async operation
      await new Promise(resolve => setTimeout(resolve, 10));
      return 'async-result';
    });
    
    expect(result).toBe('async-result');
  });

  it('should throw in test environment when budget exceeded', () => {
    const originalEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'test';
    
    expect(() => {
      PerformanceBudget.measure('file-operation', () => {
        // Simulate slow operation that exceeds 50ms budget
        const start = Date.now();
        while (Date.now() - start < 60) {
          // Busy wait
        }
        return 'slow-result';
      });
    }).toThrow(/Performance budget exceeded/);
    
    process.env.NODE_ENV = originalEnv;
  });

  it('should warn in production when budget exceeded', () => {
    const originalEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    
    PerformanceBudget.measure('file-operation', () => {
      // Simulate slow operation
      const start = Date.now();
      while (Date.now() - start < 60) {
        // Busy wait
      }
      return 'slow-result';
    });
    
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('Performance warning'));
    
    process.env.NODE_ENV = originalEnv;
  });

  it('should generate performance report', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    
    // Add some measurements
    PerformanceBudget.measure('file-operation', () => 'fast');
    PerformanceBudget.measure('api-response', () => 'fast');
    
    PerformanceBudget.report();
    
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('Performance Report'));
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('file-operation'));
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('api-response'));
  });
});
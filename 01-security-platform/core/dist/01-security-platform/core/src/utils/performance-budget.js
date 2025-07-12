export const BUDGETS = {
    // Your actual requirements from PRD
    'aes-encryption': 80, // ms
    'aes-decryption': 20, // ms
    'rsa-signing': 300, // ms
    'api-response': 100, // ms
    'context-storage': 100, // ms
    'context-retrieval': 50, // ms
    'sandbox-creation': 100, // ms
    'robot-command': 100, // ms
    'file-operation': 50, // ms
    'mcp-request': 100, // ms
};
export class PerformanceBudget {
    static measurements = new Map();
    static measure(operation, fn) {
        const start = performance.now();
        try {
            const result = fn();
            const duration = performance.now() - start;
            this.record(operation, duration);
            return result;
        }
        catch (error) {
            const duration = performance.now() - start;
            this.record(operation, duration);
            throw error;
        }
    }
    static async measureAsync(operation, fn) {
        const start = performance.now();
        try {
            const result = await fn();
            const duration = performance.now() - start;
            this.record(operation, duration);
            return result;
        }
        catch (error) {
            const duration = performance.now() - start;
            this.record(operation, duration);
            throw error;
        }
    }
    static record(operation, duration) {
        const budget = BUDGETS[operation];
        // Track for statistics
        if (!this.measurements.has(operation)) {
            this.measurements.set(operation, []);
        }
        this.measurements.get(operation).push(duration);
        // Fail fast in tests
        if (process.env.NODE_ENV === 'test' && duration > budget) {
            throw new Error(`Performance budget exceeded: ${operation} took ${duration.toFixed(2)}ms ` +
                `(budget: ${budget}ms)`);
        }
        // Warn in production
        if (duration > budget) {
            console.warn(`⚠️ Performance warning: ${operation} took ${duration.toFixed(2)}ms (budget: ${budget}ms)`);
        }
    }
    static report() {
        console.log('\n📊 Performance Report:');
        for (const [operation, times] of this.measurements) {
            const sorted = times.sort((a, b) => a - b);
            const p50 = sorted[Math.floor(sorted.length * 0.5)];
            const p95 = sorted[Math.floor(sorted.length * 0.95)];
            const budget = BUDGETS[operation];
            const status = p95 <= budget ? '✅' : '❌';
            console.log(`${status} ${operation}: p50=${p50.toFixed(2)}ms, p95=${p95.toFixed(2)}ms (budget: ${budget}ms)`);
        }
    }
    static reset() {
        this.measurements.clear();
    }
}
//# sourceMappingURL=performance-budget.js.map
export declare const BUDGETS: {
    readonly 'aes-encryption': 80;
    readonly 'aes-decryption': 20;
    readonly 'rsa-signing': 300;
    readonly 'api-response': 100;
    readonly 'context-storage': 100;
    readonly 'context-retrieval': 50;
    readonly 'sandbox-creation': 100;
    readonly 'robot-command': 100;
    readonly 'file-operation': 50;
    readonly 'mcp-request': 100;
};
export declare class PerformanceBudget {
    private static measurements;
    static measure<T>(operation: keyof typeof BUDGETS, fn: () => T): T;
    static measureAsync<T>(operation: keyof typeof BUDGETS, fn: () => Promise<T>): Promise<T>;
    private static record;
    static report(): void;
    static reset(): void;
}

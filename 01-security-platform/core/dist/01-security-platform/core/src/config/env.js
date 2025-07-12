const REQUIRED_ENV_VARS = [
    'NODE_ENV',
    'CLASSIFICATION_LEVEL',
    'LOG_LEVEL',
];
const OPTIONAL_ENV_VARS = [
    'MAESTRO_ENABLED',
    'MCP_TIMEOUT',
    'MAX_ROBOTS',
    'DATABASE_URL',
    'ALCUB3_SANDBOX',
    'GEMINI_API_KEY',
    'DEBUG',
];
export function loadEnv() {
    // Check required vars
    const missing = REQUIRED_ENV_VARS.filter(key => !process.env[key]);
    if (missing.length > 0) {
        console.error(`❌ Missing required environment variables: ${missing.join(', ')}`);
        console.error(`   Set them in .env or export them before running.`);
        process.exit(1);
    }
    // Validate values
    const nodeEnv = process.env.NODE_ENV;
    if (!['development', 'test', 'production'].includes(nodeEnv)) {
        console.error(`❌ Invalid NODE_ENV: ${nodeEnv}`);
        console.error(`   Must be: development, test, or production`);
        process.exit(1);
    }
    const classificationLevel = process.env.CLASSIFICATION_LEVEL;
    if (!['UNCLASSIFIED', 'SECRET', 'TOP_SECRET'].includes(classificationLevel)) {
        console.error(`❌ Invalid CLASSIFICATION_LEVEL: ${classificationLevel}`);
        process.exit(1);
    }
    const logLevel = process.env.LOG_LEVEL;
    if (!['debug', 'info', 'warn', 'error'].includes(logLevel)) {
        console.error(`❌ Invalid LOG_LEVEL: ${logLevel}`);
        console.error(`   Must be: debug, info, warn, or error`);
        process.exit(1);
    }
    return {
        // Required
        NODE_ENV: nodeEnv,
        CLASSIFICATION_LEVEL: classificationLevel,
        LOG_LEVEL: logLevel,
        // Optional with defaults
        MAESTRO_ENABLED: process.env.MAESTRO_ENABLED,
        MCP_TIMEOUT: process.env.MCP_TIMEOUT,
        MAX_ROBOTS: process.env.MAX_ROBOTS,
        DATABASE_URL: process.env.DATABASE_URL,
        ALCUB3_SANDBOX: process.env.ALCUB3_SANDBOX,
        GEMINI_API_KEY: process.env.GEMINI_API_KEY,
        DEBUG: process.env.DEBUG,
        // Computed
        isDevelopment: nodeEnv === 'development',
        isProduction: nodeEnv === 'production',
        isTest: nodeEnv === 'test',
        isClassified: classificationLevel !== 'UNCLASSIFIED',
        isDebug: process.env.DEBUG === '1' || process.env.DEBUG === 'true',
    };
}
// Load and export (only if not in test environment)
export const env = process.env.NODE_ENV === 'test'
    ? {}
    : loadEnv();
// Prevent accidental logging in production
if (env.isProduction) {
    const originalLog = console.log;
    console.log = (...args) => {
        if (args.some(arg => typeof arg === 'string' &&
            (arg.includes('SECRET') || arg.includes('KEY') || arg.includes('PASSWORD')))) {
            originalLog('❌ Attempted to log sensitive data');
            return;
        }
        originalLog(...args);
    };
}
//# sourceMappingURL=env.js.map
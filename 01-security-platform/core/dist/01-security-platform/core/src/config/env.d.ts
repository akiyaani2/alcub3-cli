declare const REQUIRED_ENV_VARS: readonly ["NODE_ENV", "CLASSIFICATION_LEVEL", "LOG_LEVEL"];
declare const OPTIONAL_ENV_VARS: readonly ["MAESTRO_ENABLED", "MCP_TIMEOUT", "MAX_ROBOTS", "DATABASE_URL", "ALCUB3_SANDBOX", "GEMINI_API_KEY", "DEBUG"];
type RequiredEnvVars = {
    [K in typeof REQUIRED_ENV_VARS[number]]: string;
};
type OptionalEnvVars = {
    [K in typeof OPTIONAL_ENV_VARS[number]]?: string;
};
export type EnvConfig = RequiredEnvVars & OptionalEnvVars & {
    isDevelopment: boolean;
    isProduction: boolean;
    isTest: boolean;
    isClassified: boolean;
    isDebug: boolean;
};
export declare function loadEnv(): EnvConfig;
export declare const env: EnvConfig;
export {};

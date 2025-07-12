import { Command } from 'commander';
export declare class MaestroCommands {
    private securityFrameworkPath;
    private apiClient;
    private defaultApiUrl;
    constructor();
    registerCommands(program: Command): void;
    private handleScanDefaults;
    private monitorScanProgress;
    private performRemediation;
    private displayFinalReport;
    private handleScanWizard;
    private handleListScans;
    private handleGetReport;
}
export declare function registerMaestroCommands(program: Command): void;

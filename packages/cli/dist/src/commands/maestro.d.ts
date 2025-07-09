import { Command } from 'commander';
export declare class MaestroCommands {
    private securityFrameworkPath;
    constructor();
    registerCommands(program: Command): void;
    private handleScanDefaults;
}
export declare function registerMaestroCommands(program: Command): void;

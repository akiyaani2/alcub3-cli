import chalk from 'chalk';
import { spawn } from 'child_process';
import path from 'path';
export class MaestroCommands {
    securityFrameworkPath;
    constructor() {
        this.securityFrameworkPath = path.join(process.cwd(), 'security-framework', 'src');
    }
    registerCommands(program) {
        const maestroCmd = program
            .command('maestro')
            .description('MAESTRO security framework commands');
        maestroCmd
            .command('scan-defaults')
            .description('Scan for CISA top 10 misconfigurations')
            .option('--target <ip-range>', 'Target IP range to scan')
            .action(async (options) => {
            await this.handleScanDefaults(options);
        });
    }
    async handleScanDefaults(options) {
        console.log(chalk.blue('MAESTRO: Scanning for default misconfigurations...'));
        if (!options.target) {
            console.error(chalk.red('Error: --target <ip-range> is required.'));
            return;
        }
        const scriptPath = path.join(this.securityFrameworkPath, 'scan_defaults.py');
        const pythonProcess = spawn('python3', [scriptPath, '--target', options.target], {
            stdio: ['pipe', 'pipe', 'pipe']
        });
        let output = '';
        let errorOutput = '';
        pythonProcess.stdout.on('data', (data) => {
            output += data.toString();
        });
        pythonProcess.stderr.on('data', (data) => {
            errorOutput += data.toString();
        });
        pythonProcess.on('close', (code) => {
            if (code === 0) {
                try {
                    const result = JSON.parse(output.trim());
                    console.log(chalk.green('Scan complete:'));
                    console.log(JSON.stringify(result, null, 2));
                }
                catch (parseError) {
                    console.error(chalk.red('Error parsing Python script output:'), parseError);
                }
            }
            else {
                console.error(chalk.red('Error executing Python script:'));
                console.error(errorOutput);
            }
        });
    }
}
export function registerMaestroCommands(program) {
    const maestroCommands = new MaestroCommands();
    maestroCommands.registerCommands(program);
}
//# sourceMappingURL=maestro.js.map
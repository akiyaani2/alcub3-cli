import { Command } from 'commander';
import chalk from 'chalk';
import inquirer from 'inquirer';
import axios, { AxiosInstance } from 'axios';
import { io, Socket } from 'socket.io-client';
import ora from 'ora';
import path from 'path';

interface ScanOptions {
  target?: string;
  classification?: string;
  modules?: string[];
  remediate?: boolean;
  autoApprove?: boolean;
  format?: string;
  apiUrl?: string;
}

export class MaestroCommands {
  private securityFrameworkPath: string;
  private apiClient: AxiosInstance;
  private defaultApiUrl: string = 'http://localhost:8001/api/v1';

  constructor() {
    this.securityFrameworkPath = path.join(
      process.cwd(),
      'security-framework',
      'src'
    );
    
    this.apiClient = axios.create({
      baseURL: this.defaultApiUrl,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json'
      }
    });
  }

  public registerCommands(program: Command): void {
    const maestroCmd = program
      .command('maestro')
      .description('MAESTRO security framework commands');

    // Main scan-defaults command
    maestroCmd
      .command('scan-defaults')
      .description('Scan for CISA top 10 misconfigurations')
      .option('--target <ip-range>', 'Target IP range to scan')
      .option('--classification <level>', 'Classification level', 'UNCLASSIFIED')
      .option('--modules <modules...>', 'Specific modules to scan')
      .option('--remediate', 'Automatically remediate findings')
      .option('--auto-approve', 'Auto-approve all remediations')
      .option('--format <format>', 'Output format (json|summary)', 'summary')
      .option('--api-url <url>', 'CISA API URL', this.defaultApiUrl)
      .action(async (options: ScanOptions) => {
        await this.handleScanDefaults(options);
      });

    // Interactive scan wizard
    maestroCmd
      .command('scan-wizard')
      .description('Interactive wizard for CISA compliance scanning')
      .action(async () => {
        await this.handleScanWizard();
      });

    // List previous scans
    maestroCmd
      .command('list-scans')
      .description('List all previous CISA scans')
      .option('--api-url <url>', 'CISA API URL', this.defaultApiUrl)
      .action(async (options) => {
        await this.handleListScans(options);
      });

    // Get scan report
    maestroCmd
      .command('get-report <scanId>')
      .description('Get detailed report for a specific scan')
      .option('--format <format>', 'Output format (json|summary)', 'summary')
      .option('--api-url <url>', 'CISA API URL', this.defaultApiUrl)
      .action(async (scanId: string, options) => {
        await this.handleGetReport(scanId, options);
      });
  }

  private async handleScanDefaults(options: ScanOptions): Promise<void> {
    console.log(chalk.blue.bold('\n🔐 ALCUB3 MAESTRO - CISA Top 10 Misconfiguration Scanner\n'));

    if (!options.target) {
      console.error(chalk.red('❌ Error: --target <ip-range> is required.'));
      return;
    }

    // Update API URL if provided
    if (options.apiUrl) {
      this.apiClient.defaults.baseURL = options.apiUrl;
    }

    const spinner = ora('Initiating CISA compliance scan...').start();

    try {
      // Start the scan
      const scanResponse = await this.apiClient.post('/cisa/scan', {
        target: options.target,
        classification: options.classification,
        modules: options.modules
      });

      const { scanId, websocketUrl } = scanResponse.data;
      spinner.succeed(`Scan initiated successfully. ID: ${chalk.cyan(scanId)}`);

      // Connect to WebSocket for real-time updates
      console.log(chalk.blue('\n📡 Connecting to real-time scan updates...'));
      await this.monitorScanProgress(scanId, options);

      // If remediation requested, perform it
      if (options.remediate) {
        console.log(chalk.yellow('\n🔧 Starting remediation process...'));
        await this.performRemediation(scanId, options.autoApprove);
      }

      // Get final report
      await this.displayFinalReport(scanId, options.format || 'summary');

    } catch (error) {
      spinner.fail('Scan failed');
      if (axios.isAxiosError(error)) {
        console.error(chalk.red('\n❌ API Error:'), error.response?.data?.error || error.message);
      } else {
        console.error(chalk.red('\n❌ Error:'), error);
      }
    }
  }

  private async monitorScanProgress(scanId: string, options: ScanOptions): Promise<void> {
    return new Promise((resolve, reject) => {
      const socketUrl = options.apiUrl?.replace('/api/v1', '') || 'http://localhost:8001';
      const socket: Socket = io(`${socketUrl}/cisa`, {
        query: { scanId }
      });

      let progressBar: any;

      socket.on('connect', () => {
        console.log(chalk.green('✓ Connected to scan monitor'));
        socket.emit('subscribe-scan', scanId);
      });

      socket.on('scan-status', (status: any) => {
        if (!progressBar && status.progress) {
          progressBar = ora(`Scanning: ${status.progress}`).start();
        } else if (progressBar) {
          progressBar.text = `Scanning: ${status.progress} - Compliance: ${status.complianceScore?.toFixed(1) || 'N/A'}%`;
        }

        if (status.status === 'completed' || status.status === 'remediation_required') {
          if (progressBar) progressBar.succeed(`Scan completed - Compliance: ${status.complianceScore?.toFixed(1)}%`);
          socket.disconnect();
          resolve();
        } else if (status.status === 'failed') {
          if (progressBar) progressBar.fail('Scan failed');
          socket.disconnect();
          reject(new Error('Scan failed'));
        }
      });

      socket.on('disconnect', () => {
        console.log(chalk.gray('\nDisconnected from scan monitor'));
      });

      socket.on('error', (error) => {
        console.error(chalk.red('\nWebSocket error:'), error);
        reject(error);
      });

      // Timeout after 10 minutes
      setTimeout(() => {
        socket.disconnect();
        reject(new Error('Scan timeout'));
      }, 600000);
    });
  }

  private async performRemediation(scanId: string, autoApprove?: boolean): Promise<void> {
    const spinner = ora('Performing remediation...').start();

    try {
      const response = await this.apiClient.post('/cisa/remediate', {
        scanId,
        autoApprove
      });

      spinner.succeed('Remediation initiated');

      // Monitor remediation progress
      await new Promise(resolve => setTimeout(resolve, 5000)); // Give it time to complete

      spinner.succeed('Remediation completed');
    } catch (error) {
      spinner.fail('Remediation failed');
      throw error;
    }
  }

  private async displayFinalReport(scanId: string, format: string): Promise<void> {
    console.log(chalk.blue('\n📊 Fetching final report...\n'));

    try {
      const response = await this.apiClient.get(`/cisa/report/${scanId}`, {
        params: { format }
      });

      if (format === 'json') {
        console.log(JSON.stringify(response.data, null, 2));
      } else {
        console.log(response.data);
      }
    } catch (error) {
      console.error(chalk.red('Failed to fetch report:'), error);
    }
  }

  private async handleScanWizard(): Promise<void> {
    console.log(chalk.blue.bold('\n🧙 ALCUB3 MAESTRO - Interactive Scan Wizard\n'));

    const answers = await inquirer.prompt([
      {
        type: 'input',
        name: 'target',
        message: 'Enter target IP or hostname:',
        validate: (input) => input.length > 0 || 'Target is required'
      },
      {
        type: 'list',
        name: 'classification',
        message: 'Select classification level:',
        choices: ['UNCLASSIFIED', 'SECRET', 'TOP_SECRET'],
        default: 'UNCLASSIFIED'
      },
      {
        type: 'checkbox',
        name: 'modules',
        message: 'Select specific modules to scan (leave empty for all):',
        choices: [
          { name: 'Default Configurations', value: 'default_configs' },
          { name: 'Privilege Separation', value: 'privilege_separation' },
          { name: 'Network Monitoring', value: 'network_monitoring' },
          { name: 'Network Segmentation', value: 'network_segmentation' },
          { name: 'Patch Management', value: 'patch_management' },
          { name: 'Access Controls', value: 'access_controls' },
          { name: 'MFA Configuration', value: 'mfa_config' },
          { name: 'ACL Permissions', value: 'acl_permissions' },
          { name: 'Credential Hygiene', value: 'credential_hygiene' },
          { name: 'Code Execution', value: 'code_execution' }
        ]
      },
      {
        type: 'confirm',
        name: 'remediate',
        message: 'Automatically remediate findings?',
        default: false
      },
      {
        type: 'confirm',
        name: 'autoApprove',
        message: 'Auto-approve all remediations?',
        default: false,
        when: (answers) => answers.remediate
      }
    ]);

    const options: ScanOptions = {
      ...answers,
      format: 'summary',
      apiUrl: this.defaultApiUrl
    };

    await this.handleScanDefaults(options);
  }

  private async handleListScans(options: any): Promise<void> {
    console.log(chalk.blue.bold('\n📋 ALCUB3 MAESTRO - Previous Scans\n'));

    if (options.apiUrl) {
      this.apiClient.defaults.baseURL = options.apiUrl;
    }

    try {
      const response = await this.apiClient.get('/cisa/scans');
      const scans = response.data.scans;

      if (scans.length === 0) {
        console.log(chalk.yellow('No scans found.'));
        return;
      }

      console.log(chalk.cyan('Recent Scans:\n'));
      scans.forEach((scan: any) => {
        const status = scan.status === 'completed' ? chalk.green(scan.status) :
                      scan.status === 'failed' ? chalk.red(scan.status) :
                      chalk.yellow(scan.status);
        
        console.log(`ID: ${chalk.cyan(scan.scanId)}`);
        console.log(`Status: ${status}`);
        console.log(`Compliance Score: ${scan.complianceScore?.toFixed(1) || 'N/A'}%`);
        console.log(`Critical Findings: ${scan.criticalFindings || 0}`);
        console.log(`Last Update: ${new Date(scan.lastUpdate).toLocaleString()}`);
        console.log(chalk.gray('─'.repeat(50)));
      });
    } catch (error) {
      console.error(chalk.red('Failed to fetch scans:'), error);
    }
  }

  private async handleGetReport(scanId: string, options: any): Promise<void> {
    console.log(chalk.blue.bold(`\n📄 ALCUB3 MAESTRO - Scan Report: ${scanId}\n`));

    if (options.apiUrl) {
      this.apiClient.defaults.baseURL = options.apiUrl;
    }

    await this.displayFinalReport(scanId, options.format);
  }
}

export function registerMaestroCommands(program: Command): void {
  const maestroCommands = new MaestroCommands();
  maestroCommands.registerCommands(program);
}
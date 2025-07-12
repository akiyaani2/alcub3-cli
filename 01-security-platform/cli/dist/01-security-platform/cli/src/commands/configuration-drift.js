/**
 * Copyright 2024 ALCUB3 Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import inquirer from 'inquirer';
import { Table } from 'console-table-printer';
import { readFileSync, writeFileSync } from 'fs';
class ConfigurationDriftCLI {
    apiUrl;
    authToken;
    constructor() {
        this.apiUrl = process.env.ALCUB3_API_URL || 'http://localhost:3000';
        this.authToken = process.env.ALCUB3_AUTH_TOKEN || '';
    }
    async makeRequest(endpoint, method = 'GET', body) {
        const url = `${this.apiUrl}/api/v1/drift${endpoint}`;
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.authToken}`,
            },
        };
        if (body) {
            options.body = JSON.stringify(body);
        }
        try {
            const response = await fetch(url, options);
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || `HTTP ${response.status}`);
            }
            return data;
        }
        catch (error) {
            throw new Error(`API request failed: ${error.message}`);
        }
    }
    async createBaseline(options) {
        const spinner = ora('Creating configuration baseline...').start();
        try {
            const request = {
                target_systems: options.systems ? options.systems.split(',') : ['localhost'],
                baseline_type: options.type || 'full_system',
                scopes: options.scopes ? options.scopes.split(',') : ['filesystem', 'services', 'security', 'maestro'],
                metadata: {
                    description: options.description || 'Configuration baseline',
                    tags: options.tags ? options.tags.split(',') : []
                }
            };
            const result = await this.makeRequest('/baselines', 'POST', request);
            spinner.succeed('Configuration baseline created successfully');
            console.log('\n' + chalk.green('✓ Baseline Created'));
            console.log(chalk.cyan(`Baseline ID: ${result.baseline.baseline_id}`));
            console.log(chalk.cyan(`Type: ${result.baseline.baseline_type}`));
            console.log(chalk.cyan(`Classification: ${result.baseline.classification_level}`));
            console.log(chalk.cyan(`Target Systems: ${result.baseline.target_systems.join(', ')}`));
            console.log(chalk.cyan(`Configuration Items: ${result.baseline.configuration_items.length}`));
            console.log(chalk.cyan(`Status: ${result.baseline.status}`));
            if (options.save) {
                const filename = `baseline_${result.baseline.baseline_id}.json`;
                writeFileSync(filename, JSON.stringify(result.baseline, null, 2));
                console.log(chalk.yellow(`\nBaseline saved to: ${filename}`));
            }
        }
        catch (error) {
            spinner.fail('Failed to create baseline');
            console.error(chalk.red(`Error: ${error.message}`));
            process.exit(1);
        }
    }
    async listBaselines(options) {
        const spinner = ora('Retrieving configuration baselines...').start();
        try {
            const queryParams = new URLSearchParams();
            if (options.type)
                queryParams.append('baseline_type', options.type);
            if (options.classification)
                queryParams.append('classification_level', options.classification);
            if (options.status)
                queryParams.append('status', options.status);
            const result = await this.makeRequest(`/baselines?${queryParams.toString()}`);
            spinner.succeed('Configuration baselines retrieved');
            if (result.baselines.length === 0) {
                console.log(chalk.yellow('No baselines found'));
                return;
            }
            const table = new Table({
                title: 'Configuration Baselines',
                columns: [
                    { name: 'baseline_id', title: 'Baseline ID', alignment: 'left' },
                    { name: 'baseline_type', title: 'Type', alignment: 'left' },
                    { name: 'classification_level', title: 'Classification', alignment: 'left' },
                    { name: 'target_systems', title: 'Target Systems', alignment: 'left' },
                    { name: 'configuration_items', title: 'Items', alignment: 'right' },
                    { name: 'status', title: 'Status', alignment: 'left' },
                    { name: 'created_by', title: 'Created By', alignment: 'left' }
                ]
            });
            result.baselines.forEach((baseline) => {
                table.addRow({
                    baseline_id: baseline.baseline_id.substring(0, 20) + '...',
                    baseline_type: baseline.baseline_type,
                    classification_level: baseline.classification_level,
                    target_systems: baseline.target_systems.join(', '),
                    configuration_items: baseline.configuration_items,
                    status: baseline.status,
                    created_by: baseline.created_by
                });
            });
            table.printTable();
        }
        catch (error) {
            spinner.fail('Failed to retrieve baselines');
            console.error(chalk.red(`Error: ${error.message}`));
            process.exit(1);
        }
    }
    async detectDrift(options) {
        const spinner = ora('Detecting configuration drift...').start();
        try {
            const request = {
                baseline_id: options.baseline,
                detection_method: options.method || 'hybrid',
                sensitivity_level: options.sensitivity || 'medium',
                current_config: options.config ? JSON.parse(readFileSync(options.config, 'utf8')) : {}
            };
            const result = await this.makeRequest('/detect', 'POST', request);
            spinner.succeed('Configuration drift detection completed');
            console.log('\n' + chalk.green('✓ Drift Detection Results'));
            console.log(chalk.cyan(`Detection ID: ${result.detection_result.detection_id}`));
            console.log(chalk.cyan(`Baseline ID: ${result.detection_result.baseline_id}`));
            console.log(chalk.cyan(`Analysis Timestamp: ${new Date(result.detection_result.analysis_timestamp * 1000).toISOString()}`));
            if (result.detection_result.anomaly_detected) {
                console.log(chalk.red(`\n⚠️  Configuration Drift Detected`));
                console.log(chalk.red(`Overall Drift Score: ${result.detection_result.overall_drift_score.toFixed(2)}`));
                console.log(chalk.red(`Risk Level: ${result.detection_result.risk_level}`));
                console.log(chalk.red(`Total Changes: ${result.detection_result.total_changes}`));
                console.log(chalk.red(`Critical Changes: ${result.detection_result.critical_changes}`));
                if (result.detection_result.drift_events.length > 0) {
                    console.log(chalk.yellow('\nDrift Events:'));
                    const table = new Table({
                        columns: [
                            { name: 'path', title: 'Configuration Path', alignment: 'left' },
                            { name: 'change_type', title: 'Change Type', alignment: 'left' },
                            { name: 'severity', title: 'Severity', alignment: 'left' },
                            { name: 'drift_score', title: 'Score', alignment: 'right' },
                            { name: 'confidence', title: 'Confidence', alignment: 'right' }
                        ]
                    });
                    result.detection_result.drift_events.forEach((event) => {
                        table.addRow({
                            path: event.configuration_path,
                            change_type: event.change_type,
                            severity: event.severity,
                            drift_score: event.drift_score.toFixed(2),
                            confidence: (event.confidence * 100).toFixed(1) + '%'
                        });
                    });
                    table.printTable();
                }
                if (result.detection_result.recommendations.length > 0) {
                    console.log(chalk.yellow('\nRecommendations:'));
                    result.detection_result.recommendations.forEach((rec, index) => {
                        console.log(chalk.yellow(`${index + 1}. ${rec}`));
                    });
                }
                // Ask if user wants to create remediation plan
                if (options.interactive) {
                    const answer = await inquirer.prompt([
                        {
                            type: 'confirm',
                            name: 'remediate',
                            message: 'Would you like to create a remediation plan for these drift events?',
                            default: false
                        }
                    ]);
                    if (answer.remediate) {
                        await this.createRemediationPlan({
                            baseline: options.baseline,
                            driftEvents: result.detection_result.drift_events,
                            autoApprove: false
                        });
                    }
                }
            }
            else {
                console.log(chalk.green(`\n✓ No Configuration Drift Detected`));
                console.log(chalk.green(`System configuration matches baseline`));
            }
            if (options.save) {
                const filename = `drift_detection_${result.detection_result.detection_id}.json`;
                writeFileSync(filename, JSON.stringify(result.detection_result, null, 2));
                console.log(chalk.yellow(`\nDetection results saved to: ${filename}`));
            }
        }
        catch (error) {
            spinner.fail('Failed to detect drift');
            console.error(chalk.red(`Error: ${error.message}`));
            process.exit(1);
        }
    }
    async startMonitoring(options) {
        const spinner = ora('Starting configuration monitoring...').start();
        try {
            const request = {
                baseline_id: options.baseline,
                target_systems: options.systems ? options.systems.split(',') : ['localhost'],
                monitoring_interval_seconds: options.interval || 300,
                alert_thresholds: {
                    critical: options.criticalThreshold || 8.0,
                    high: options.highThreshold || 6.0,
                    medium: options.mediumThreshold || 4.0
                },
                notification_channels: options.channels ? options.channels.split(',') : ['email', 'dashboard'],
                auto_remediation_enabled: options.autoRemediation || false,
                monitoring_scopes: options.scopes ? options.scopes.split(',') : ['filesystem', 'services', 'security']
            };
            const result = await this.makeRequest('/monitor', 'POST', request);
            spinner.succeed('Configuration monitoring started');
            console.log('\n' + chalk.green('✓ Monitoring Started'));
            console.log(chalk.cyan(`Baseline ID: ${result.monitoring_config.baseline_id}`));
            console.log(chalk.cyan(`Target Systems: ${result.monitoring_config.target_systems.join(', ')}`));
            console.log(chalk.cyan(`Monitoring Interval: ${result.monitoring_config.monitoring_interval_seconds} seconds`));
            console.log(chalk.cyan(`Started By: ${result.monitoring_config.started_by}`));
        }
        catch (error) {
            spinner.fail('Failed to start monitoring');
            console.error(chalk.red(`Error: ${error.message}`));
            process.exit(1);
        }
    }
    async getMonitoringStatus(options) {
        const spinner = ora('Retrieving monitoring status...').start();
        try {
            const result = await this.makeRequest('/monitor');
            spinner.succeed('Monitoring status retrieved');
            console.log('\n' + chalk.green('✓ Monitoring Status'));
            console.log(chalk.cyan(`Status: ${result.monitoring_status.status}`));
            console.log(chalk.cyan(`Active Configurations: ${result.monitoring_status.active_configurations}`));
            console.log(chalk.cyan(`Total Scans: ${result.monitoring_status.total_scans}`));
            console.log(chalk.cyan(`Alerts Generated: ${result.monitoring_status.alerts_generated}`));
            console.log(chalk.cyan(`Average Scan Time: ${result.monitoring_status.average_scan_time_ms.toFixed(2)}ms`));
            console.log(chalk.cyan(`Uptime: ${(result.monitoring_status.uptime_seconds / 3600).toFixed(1)} hours`));
            console.log(chalk.cyan(`False Positive Rate: ${(result.monitoring_status.false_positive_rate * 100).toFixed(1)}%`));
        }
        catch (error) {
            spinner.fail('Failed to retrieve monitoring status');
            console.error(chalk.red(`Error: ${error.message}`));
            process.exit(1);
        }
    }
    async stopMonitoring(options) {
        const spinner = ora('Stopping configuration monitoring...').start();
        try {
            const result = await this.makeRequest(`/monitor/${options.baseline}`, 'DELETE');
            spinner.succeed('Configuration monitoring stopped');
            console.log('\n' + chalk.green('✓ Monitoring Stopped'));
            console.log(chalk.cyan(`Baseline ID: ${options.baseline}`));
        }
        catch (error) {
            spinner.fail('Failed to stop monitoring');
            console.error(chalk.red(`Error: ${error.message}`));
            process.exit(1);
        }
    }
    async createRemediationPlan(options) {
        const spinner = ora('Creating remediation plan...').start();
        try {
            const request = {
                baseline_id: options.baseline,
                drift_events: options.driftEvents || [],
                target_system: options.target || 'localhost',
                auto_approve: options.autoApprove || false
            };
            const result = await this.makeRequest('/remediate', 'POST', request);
            spinner.succeed('Remediation plan created');
            console.log('\n' + chalk.green('✓ Remediation Plan Created'));
            console.log(chalk.cyan(`Plan ID: ${result.remediation_result.plan_id}`));
            console.log(chalk.cyan(`Status: ${result.remediation_result.status}`));
            if (result.remediation_result.status === 'requires_approval') {
                console.log(chalk.yellow(`\n⚠️  Manual Approval Required`));
                console.log(chalk.yellow(`Approval Level: ${result.remediation_result.approval_required}`));
                console.log(chalk.yellow(`Use 'alcub3 drift remediate approve' to approve this plan`));
            }
            else if (result.remediation_result.status === 'completed') {
                console.log(chalk.green(`\n✓ Remediation Completed`));
                console.log(chalk.green(`Steps Completed: ${result.remediation_result.steps_completed}`));
                console.log(chalk.green(`Success Rate: ${(result.remediation_result.success_rate * 100).toFixed(1)}%`));
                console.log(chalk.green(`Execution Time: ${result.remediation_result.execution_time_seconds.toFixed(2)} seconds`));
            }
        }
        catch (error) {
            spinner.fail('Failed to create remediation plan');
            console.error(chalk.red(`Error: ${error.message}`));
            process.exit(1);
        }
    }
    async executeRemediation(options) {
        const spinner = ora('Executing remediation plan...').start();
        try {
            const request = {
                force_execute: options.force || false,
                approval_override: options.override || false
            };
            const result = await this.makeRequest(`/remediate/${options.plan}/execute`, 'POST', request);
            spinner.succeed('Remediation execution completed');
            console.log('\n' + chalk.green('✓ Remediation Executed'));
            console.log(chalk.cyan(`Result ID: ${result.execution_result.result_id}`));
            console.log(chalk.cyan(`Status: ${result.execution_result.status}`));
            console.log(chalk.cyan(`Steps Completed: ${result.execution_result.steps_completed}`));
            console.log(chalk.cyan(`Steps Failed: ${result.execution_result.steps_failed}`));
            console.log(chalk.cyan(`Success Rate: ${(result.execution_result.success_rate * 100).toFixed(1)}%`));
            console.log(chalk.cyan(`Execution Time: ${result.execution_result.execution_time_seconds.toFixed(2)} seconds`));
            if (result.execution_result.rollback_performed) {
                console.log(chalk.yellow(`\n⚠️  Rollback Performed`));
                console.log(chalk.yellow(`Reason: Low success rate or critical failure`));
            }
            if (result.execution_result.error_messages.length > 0) {
                console.log(chalk.red(`\n❌ Errors:`));
                result.execution_result.error_messages.forEach((error, index) => {
                    console.log(chalk.red(`${index + 1}. ${error}`));
                });
            }
        }
        catch (error) {
            spinner.fail('Failed to execute remediation');
            console.error(chalk.red(`Error: ${error.message}`));
            process.exit(1);
        }
    }
    async approveRemediation(options) {
        const spinner = ora('Processing remediation approval...').start();
        try {
            const request = {
                approved: options.approve !== false,
                comments: options.comments || ''
            };
            const result = await this.makeRequest(`/remediate/${options.plan}/approve`, 'POST', request);
            spinner.succeed('Remediation approval processed');
            console.log('\n' + chalk.green('✓ Approval Processed'));
            console.log(chalk.cyan(`Plan ID: ${options.plan}`));
            console.log(chalk.cyan(`Decision: ${request.approved ? 'Approved' : 'Rejected'}`));
            if (request.approved && result.approval_result) {
                console.log(chalk.green(`\n✓ Remediation Executed`));
                console.log(chalk.green(`Status: ${result.approval_result.status}`));
                console.log(chalk.green(`Success Rate: ${(result.approval_result.success_rate * 100).toFixed(1)}%`));
            }
        }
        catch (error) {
            spinner.fail('Failed to process approval');
            console.error(chalk.red(`Error: ${error.message}`));
            process.exit(1);
        }
    }
    async listPendingApprovals(options) {
        const spinner = ora('Retrieving pending approvals...').start();
        try {
            const result = await this.makeRequest('/remediate/pending/approvals');
            spinner.succeed('Pending approvals retrieved');
            if (result.approvals.length === 0) {
                console.log(chalk.yellow('No pending approvals found'));
                return;
            }
            console.log('\n' + chalk.green('✓ Pending Approvals'));
            const table = new Table({
                columns: [
                    { name: 'plan_id', title: 'Plan ID', alignment: 'left' },
                    { name: 'approval_level', title: 'Approval Level', alignment: 'left' },
                    { name: 'estimated_duration_minutes', title: 'Duration (min)', alignment: 'right' },
                    { name: 'safety_level', title: 'Safety Level', alignment: 'left' },
                    { name: 'alert_id', title: 'Alert ID', alignment: 'left' },
                    { name: 'requested_time', title: 'Requested', alignment: 'left' }
                ]
            });
            result.approvals.forEach((approval) => {
                table.addRow({
                    plan_id: approval.plan_id.substring(0, 20) + '...',
                    approval_level: approval.approval_level,
                    estimated_duration_minutes: approval.estimated_duration_minutes,
                    safety_level: approval.safety_level,
                    alert_id: approval.alert_id.substring(0, 20) + '...',
                    requested_time: new Date(approval.requested_timestamp * 1000).toLocaleString()
                });
            });
            table.printTable();
        }
        catch (error) {
            spinner.fail('Failed to retrieve pending approvals');
            console.error(chalk.red(`Error: ${error.message}`));
            process.exit(1);
        }
    }
    async getStatistics(options) {
        const spinner = ora('Retrieving configuration drift statistics...').start();
        try {
            const queryParams = new URLSearchParams();
            if (options.timeRange)
                queryParams.append('time_range', options.timeRange);
            const result = await this.makeRequest(`/statistics?${queryParams.toString()}`);
            spinner.succeed('Statistics retrieved');
            console.log('\n' + chalk.green('✓ Configuration Drift Statistics'));
            console.log(chalk.cyan(`Time Range: ${result.statistics.time_range}`));
            console.log(chalk.cyan(`Total Baselines: ${result.statistics.total_baselines}`));
            console.log(chalk.cyan(`Active Monitoring: ${result.statistics.active_monitoring}`));
            console.log(chalk.cyan(`Drift Events Detected: ${result.statistics.drift_events_detected}`));
            console.log(chalk.cyan(`Remediation Plans Created: ${result.statistics.remediation_plans_created}`));
            console.log(chalk.cyan(`Successful Remediations: ${result.statistics.successful_remediations}`));
            console.log(chalk.cyan(`Average Drift Score: ${result.statistics.average_drift_score.toFixed(2)}`));
            console.log(chalk.cyan(`System Health: ${result.statistics.system_health}`));
        }
        catch (error) {
            spinner.fail('Failed to retrieve statistics');
            console.error(chalk.red(`Error: ${error.message}`));
            process.exit(1);
        }
    }
}
// Create command structure
export function createConfigurationDriftCommand() {
    const cli = new ConfigurationDriftCLI();
    const command = new Command('drift');
    command
        .description('Configuration drift detection and remediation commands')
        .addHelpText('after', `
Examples:
  ${chalk.yellow('alcub3 drift baseline create --systems localhost --type full_system')}
  ${chalk.yellow('alcub3 drift baseline list --type security_config')}
  ${chalk.yellow('alcub3 drift detect --baseline baseline_123 --interactive')}
  ${chalk.yellow('alcub3 drift monitor start --baseline baseline_123 --interval 300')}
  ${chalk.yellow('alcub3 drift remediate create --baseline baseline_123 --auto-approve')}
  ${chalk.yellow('alcub3 drift remediate approve --plan plan_456 --approve')}
  ${chalk.yellow('alcub3 drift statistics --time-range 24h')}
`);
    // Baseline management commands
    const baselineCommand = command
        .command('baseline')
        .description('Configuration baseline management');
    baselineCommand
        .command('create')
        .description('Create a new configuration baseline')
        .option('--systems <systems>', 'Target systems (comma-separated)', 'localhost')
        .option('--type <type>', 'Baseline type', 'full_system')
        .option('--scopes <scopes>', 'Configuration scopes (comma-separated)', 'filesystem,services,security,maestro')
        .option('--description <description>', 'Baseline description')
        .option('--tags <tags>', 'Baseline tags (comma-separated)')
        .option('--save', 'Save baseline to file')
        .action(async (options) => {
        await cli.createBaseline(options);
    });
    baselineCommand
        .command('list')
        .description('List configuration baselines')
        .option('--type <type>', 'Filter by baseline type')
        .option('--classification <level>', 'Filter by classification level')
        .option('--status <status>', 'Filter by status')
        .action(async (options) => {
        await cli.listBaselines(options);
    });
    // Drift detection commands
    command
        .command('detect')
        .description('Detect configuration drift')
        .requiredOption('--baseline <id>', 'Baseline ID to compare against')
        .option('--config <file>', 'Current configuration file (JSON)')
        .option('--method <method>', 'Detection method', 'hybrid')
        .option('--sensitivity <level>', 'Sensitivity level', 'medium')
        .option('--interactive', 'Interactive mode')
        .option('--save', 'Save detection results to file')
        .action(async (options) => {
        await cli.detectDrift(options);
    });
    // Monitoring commands
    const monitorCommand = command
        .command('monitor')
        .description('Configuration monitoring management');
    monitorCommand
        .command('start')
        .description('Start configuration monitoring')
        .requiredOption('--baseline <id>', 'Baseline ID to monitor')
        .option('--systems <systems>', 'Target systems (comma-separated)', 'localhost')
        .option('--interval <seconds>', 'Monitoring interval in seconds', '300')
        .option('--critical-threshold <threshold>', 'Critical alert threshold', '8.0')
        .option('--high-threshold <threshold>', 'High alert threshold', '6.0')
        .option('--medium-threshold <threshold>', 'Medium alert threshold', '4.0')
        .option('--channels <channels>', 'Notification channels (comma-separated)', 'email,dashboard')
        .option('--scopes <scopes>', 'Monitoring scopes (comma-separated)', 'filesystem,services,security')
        .option('--auto-remediation', 'Enable automatic remediation')
        .action(async (options) => {
        await cli.startMonitoring(options);
    });
    monitorCommand
        .command('status')
        .description('Get monitoring status')
        .action(async (options) => {
        await cli.getMonitoringStatus(options);
    });
    monitorCommand
        .command('stop')
        .description('Stop configuration monitoring')
        .requiredOption('--baseline <id>', 'Baseline ID to stop monitoring')
        .action(async (options) => {
        await cli.stopMonitoring(options);
    });
    // Remediation commands
    const remediateCommand = command
        .command('remediate')
        .description('Configuration remediation management');
    remediateCommand
        .command('create')
        .description('Create remediation plan')
        .requiredOption('--baseline <id>', 'Baseline ID')
        .option('--target <system>', 'Target system', 'localhost')
        .option('--auto-approve', 'Auto-approve remediation')
        .action(async (options) => {
        await cli.createRemediationPlan(options);
    });
    remediateCommand
        .command('execute')
        .description('Execute remediation plan')
        .requiredOption('--plan <id>', 'Remediation plan ID')
        .option('--force', 'Force execution')
        .option('--override', 'Override approval requirements')
        .action(async (options) => {
        await cli.executeRemediation(options);
    });
    remediateCommand
        .command('approve')
        .description('Approve remediation plan')
        .requiredOption('--plan <id>', 'Remediation plan ID')
        .option('--approve', 'Approve the plan', true)
        .option('--reject', 'Reject the plan')
        .option('--comments <comments>', 'Approval comments')
        .action(async (options) => {
        if (options.reject) {
            options.approve = false;
        }
        await cli.approveRemediation(options);
    });
    remediateCommand
        .command('approvals')
        .description('List pending approvals')
        .action(async (options) => {
        await cli.listPendingApprovals(options);
    });
    // Statistics and reporting
    command
        .command('statistics')
        .description('Get configuration drift statistics')
        .option('--time-range <range>', 'Time range for statistics', '24h')
        .action(async (options) => {
        await cli.getStatistics(options);
    });
    return command;
}
//# sourceMappingURL=configuration-drift.js.map
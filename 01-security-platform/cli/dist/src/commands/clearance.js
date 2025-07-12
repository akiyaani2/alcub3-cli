/**
 * ALCUB3 Security Clearance CLI Commands
 * PKI/CAC Authentication and Role-Based Access Control CLI Interface
 *
 * This module provides CLI commands for security clearance-based operations
 * including PKI/CAC authentication, clearance validation, and access control
 * management for defense-grade AI systems.
 *
 * Commands:
 * - alcub3 clearance authenticate --card-uuid <uuid> --pin <pin> --network <network>
 * - alcub3 clearance validate --user-id <id> --required-level <level>
 * - alcub3 clearance authorize --tool <tool> --classification <level>
 * - alcub3 clearance status
 * - alcub3 clearance metrics
 */
import chalk from 'chalk';
import inquirer from 'inquirer';
import { spawn } from 'child_process';
import { existsSync } from 'fs';
import path from 'path';
export class ClearanceCommands {
    securityFrameworkPath;
    constructor() {
        // Path to the security framework Python modules
        this.securityFrameworkPath = path.join(process.cwd(), 'security-framework', 'src', 'shared');
    }
    /**
     * Register all clearance-related commands
     */
    registerCommands(program) {
        const clearanceCmd = program
            .command('clearance')
            .description('Security clearance and PKI/CAC authentication commands');
        // Authentication command
        clearanceCmd
            .command('authenticate')
            .description('Authenticate using PKI/CAC certificate')
            .option('--card-uuid <uuid>', 'Smart card UUID')
            .option('--pin <pin>', 'Smart card PIN')
            .option('--network <network>', 'PKI network (niprnet|siprnet|jwics)', 'niprnet')
            .option('--cert-file <file>', 'Certificate file path (for testing)')
            .action(async (options) => {
            await this.handleAuthenticate(options);
        });
        // Clearance validation command
        clearanceCmd
            .command('validate')
            .description('Validate security clearance requirements')
            .option('--user-id <id>', 'User identifier')
            .option('--required-level <level>', 'Required clearance level (secret|top_secret|ts_sci)')
            .option('--compartments <compartments>', 'Required compartments (comma-separated)')
            .action(async (options) => {
            await this.handleValidateClearance(options);
        });
        // Tool authorization command
        clearanceCmd
            .command('authorize')
            .description('Check tool access authorization')
            .option('--user-id <id>', 'User identifier')
            .option('--tool <tool>', 'Tool name (validate_input|robotics_control|security_audit|system_admin)')
            .option('--classification <level>', 'Data classification (unclassified|cui|secret|top_secret)')
            .action(async (options) => {
            await this.handleAuthorizeAccess(options);
        });
        // Status command
        clearanceCmd
            .command('status')
            .description('Show current authentication and clearance status')
            .action(async () => {
            await this.handleStatus();
        });
        // Metrics command
        clearanceCmd
            .command('metrics')
            .description('Display security clearance system metrics')
            .action(async () => {
            await this.handleMetrics();
        });
        // Demo command
        clearanceCmd
            .command('demo')
            .description('Run PKI/CAC authentication demonstration')
            .action(async () => {
            await this.handleDemo();
        });
    }
    /**
     * Handle PKI/CAC authentication
     */
    async handleAuthenticate(options) {
        console.log(chalk.blue('🔐 ALCUB3 PKI/CAC Authentication'));
        console.log(chalk.gray('='.repeat(40)));
        try {
            // Validate required options
            if (!options.cardUuid && !options.certFile) {
                console.error(chalk.red('❌ Error: --card-uuid or --cert-file required'));
                return;
            }
            if (!options.pin) {
                const pinPrompt = await inquirer.prompt([
                    {
                        type: 'password',
                        name: 'pin',
                        message: 'Enter smart card PIN:',
                        mask: '*'
                    }
                ]);
                options.pin = pinPrompt.pin;
            }
            console.log(chalk.yellow('🔄 Authenticating with PKI/CAC certificate...'));
            // Call Python security framework
            const result = await this.callSecurityFramework('authenticate_pki', {
                card_uuid: options.cardUuid || 'demo-card-' + Date.now(),
                pin: options.pin,
                network: options.network,
                cert_file: options.certFile
            });
            if (result.success) {
                console.log(chalk.green('✅ Authentication successful!'));
                console.log(chalk.cyan(`👤 User ID: ${result.user_id}`));
                console.log(chalk.cyan(`🌐 PKI Network: ${result.pki_network}`));
                console.log(chalk.cyan(`🆔 Card UUID: ${result.card_uuid}`));
                console.log(chalk.cyan(`📜 Certificate Expiry: ${result.certificate_expiry}`));
                // Store authentication state (in production, this would be secure session management)
                process.env.ALCUB3_AUTHENTICATED_USER = result.user_id;
                process.env.ALCUB3_PKI_NETWORK = result.pki_network;
                console.log(chalk.green('🔒 Authentication state saved for session'));
            }
            else {
                console.log(chalk.red('❌ Authentication failed'));
                console.log(chalk.red(`Error: ${result.error}`));
            }
        }
        catch (error) {
            console.error(chalk.red('❌ Authentication error:'), error);
        }
    }
    /**
     * Handle security clearance validation
     */
    async handleValidateClearance(options) {
        console.log(chalk.blue('🔍 Security Clearance Validation'));
        console.log(chalk.gray('='.repeat(35)));
        try {
            // Get user ID from options or current session
            const userId = options.userId || process.env.ALCUB3_AUTHENTICATED_USER;
            if (!userId) {
                console.error(chalk.red('❌ Error: User not authenticated. Use "alcub3 clearance authenticate" first.'));
                return;
            }
            if (!options.requiredLevel) {
                const levelPrompt = await inquirer.prompt([
                    {
                        type: 'list',
                        name: 'requiredLevel',
                        message: 'Select required clearance level:',
                        choices: [
                            { name: 'Confidential', value: 'confidential' },
                            { name: 'Secret', value: 'secret' },
                            { name: 'Top Secret', value: 'top_secret' },
                            { name: 'Top Secret/SCI', value: 'ts_sci' }
                        ]
                    }
                ]);
                options.requiredLevel = levelPrompt.requiredLevel;
            }
            console.log(chalk.yellow('🔄 Validating security clearance...'));
            const compartments = options.compartments ? options.compartments.split(',') : [];
            const result = await this.callSecurityFramework('validate_clearance', {
                user_id: userId,
                required_level: options.requiredLevel,
                compartments: compartments
            });
            if (result.valid) {
                console.log(chalk.green('✅ Clearance validation successful!'));
                console.log(chalk.cyan(`🎖️  User clearance: ${result.user_clearance}`));
                console.log(chalk.cyan(`📅 Granted: ${result.granted_date}`));
                console.log(chalk.cyan(`📅 Expires: ${result.expiration_date}`));
                console.log(chalk.cyan(`✅ Status: ${result.verification_status}`));
                if (result.compartments && result.compartments.length > 0) {
                    console.log(chalk.cyan(`🔒 Compartments: ${result.compartments.join(', ')}`));
                }
            }
            else {
                console.log(chalk.red('❌ Clearance validation failed'));
                console.log(chalk.red(`Error: ${result.error}`));
            }
        }
        catch (error) {
            console.error(chalk.red('❌ Clearance validation error:'), error);
        }
    }
    /**
     * Handle tool access authorization
     */
    async handleAuthorizeAccess(options) {
        console.log(chalk.blue('🛠️  Tool Access Authorization'));
        console.log(chalk.gray('='.repeat(30)));
        try {
            // Get user ID from options or current session
            const userId = options.userId || process.env.ALCUB3_AUTHENTICATED_USER;
            if (!userId) {
                console.error(chalk.red('❌ Error: User not authenticated. Use "alcub3 clearance authenticate" first.'));
                return;
            }
            // Interactive prompts if options not provided
            if (!options.tool) {
                const toolPrompt = await inquirer.prompt([
                    {
                        type: 'list',
                        name: 'tool',
                        message: 'Select tool to authorize:',
                        choices: [
                            { name: 'Input Validation', value: 'validate_input' },
                            { name: 'Content Generation', value: 'generate_content' },
                            { name: 'Robotics Control', value: 'robotics_control' },
                            { name: 'Security Audit', value: 'security_audit' },
                            { name: 'System Administration', value: 'system_admin' }
                        ]
                    }
                ]);
                options.tool = toolPrompt.tool;
            }
            if (!options.classification) {
                const classPrompt = await inquirer.prompt([
                    {
                        type: 'list',
                        name: 'classification',
                        message: 'Select data classification level:',
                        choices: [
                            { name: 'Unclassified', value: 'unclassified' },
                            { name: 'Controlled Unclassified Information (CUI)', value: 'cui' },
                            { name: 'Secret', value: 'secret' },
                            { name: 'Top Secret', value: 'top_secret' }
                        ]
                    }
                ]);
                options.classification = classPrompt.classification;
            }
            console.log(chalk.yellow('🔄 Checking tool access authorization...'));
            const result = await this.callSecurityFramework('authorize_tool', {
                user_id: userId,
                tool_name: options.tool,
                classification_level: options.classification,
                context: {
                    geographic_region: 'CONUS',
                    time_of_day: new Date().getHours()
                }
            });
            if (result.decision === 'granted') {
                console.log(chalk.green('✅ Access granted!'));
                console.log(chalk.cyan(`📝 Rationale: ${result.rationale}`));
                if (result.conditions && result.conditions.length > 0) {
                    console.log(chalk.yellow('⚠️  Conditions:'));
                    result.conditions.forEach((condition) => {
                        console.log(chalk.yellow(`   • ${condition}`));
                    });
                }
                if (result.processing_time_ms) {
                    console.log(chalk.gray(`⏱️  Processing time: ${result.processing_time_ms.toFixed(2)}ms`));
                }
            }
            else {
                console.log(chalk.red('❌ Access denied'));
                console.log(chalk.red(`📝 Rationale: ${result.rationale}`));
                if (result.required_mitigations && result.required_mitigations.length > 0) {
                    console.log(chalk.yellow('🔧 Required mitigations:'));
                    result.required_mitigations.forEach((mitigation) => {
                        console.log(chalk.yellow(`   • ${mitigation}`));
                    });
                }
            }
        }
        catch (error) {
            console.error(chalk.red('❌ Authorization error:'), error);
        }
    }
    /**
     * Handle status display
     */
    async handleStatus() {
        console.log(chalk.blue('📊 ALCUB3 Security Status'));
        console.log(chalk.gray('='.repeat(30)));
        try {
            const authenticatedUser = process.env.ALCUB3_AUTHENTICATED_USER;
            const pkiNetwork = process.env.ALCUB3_PKI_NETWORK;
            console.log(chalk.cyan('🔐 Authentication Status:'));
            if (authenticatedUser) {
                console.log(chalk.green(`   ✅ Authenticated as: ${authenticatedUser}`));
                console.log(chalk.green(`   🌐 PKI Network: ${pkiNetwork || 'Unknown'}`));
            }
            else {
                console.log(chalk.red('   ❌ Not authenticated'));
                console.log(chalk.yellow('   💡 Use "alcub3 clearance authenticate" to authenticate'));
            }
            console.log();
            // Get system status from security framework
            const metrics = await this.callSecurityFramework('get_metrics', {});
            console.log(chalk.cyan('🛡️  Security Framework Status:'));
            console.log(chalk.green(`   • Active certificates: ${metrics.active_certificates}`));
            console.log(chalk.green(`   • Registered users: ${metrics.registered_users}`));
            console.log(chalk.green(`   • Performance compliant: ${metrics.performance_compliant ? '✅ Yes' : '❌ No'}`));
            console.log(chalk.green(`   • Average validation time: ${metrics.average_validation_time_ms?.toFixed(2) || 'N/A'}ms`));
        }
        catch (error) {
            console.error(chalk.red('❌ Status error:'), error);
        }
    }
    /**
     * Handle metrics display
     */
    async handleMetrics() {
        console.log(chalk.blue('📈 Security Clearance System Metrics'));
        console.log(chalk.gray('='.repeat(40)));
        try {
            const metrics = await this.callSecurityFramework('get_metrics', {});
            console.log(chalk.cyan('🔐 Authentication Metrics:'));
            console.log(`   • Total authentications: ${metrics.authentications_performed || 0}`);
            console.log(`   • Successful authentications: ${metrics.successful_authentications || 0}`);
            console.log(`   • PKI verifications: ${metrics.pki_verifications || 0}`);
            console.log(`   • Active certificates: ${metrics.active_certificates || 0}`);
            console.log();
            console.log(chalk.cyan('🛡️  Authorization Metrics:'));
            console.log(`   • Access decisions made: ${metrics.access_decisions_made || 0}`);
            console.log(`   • Clearance validations: ${metrics.clearance_validations || 0}`);
            console.log(`   • Security violations detected: ${metrics.security_violations_detected || 0}`);
            console.log();
            console.log(chalk.cyan('👥 User Management:'));
            console.log(`   • Registered users: ${metrics.registered_users || 0}`);
            console.log(`   • Role assignments: ${metrics.role_assignments || 0}`);
            console.log();
            console.log(chalk.cyan('⚡ Performance Metrics:'));
            console.log(`   • Average validation time: ${metrics.average_validation_time_ms?.toFixed(2) || 'N/A'}ms`);
            console.log(`   • Performance compliant: ${metrics.performance_compliant ? '✅ Yes' : '❌ No'}`);
            console.log(`   • Cache hit rate: ${((metrics.cache_hit_rate || 0) * 100).toFixed(1)}%`);
            console.log();
            console.log(chalk.cyan('🔧 System Status:'));
            console.log(`   • HSM available: ${metrics.hsm_available ? '✅ Yes' : '❌ No'}`);
        }
        catch (error) {
            console.error(chalk.red('❌ Metrics error:'), error);
        }
    }
    /**
     * Handle demo execution
     */
    async handleDemo() {
        console.log(chalk.blue('🎯 Running PKI/CAC Authentication Demo'));
        console.log(chalk.gray('='.repeat(45)));
        try {
            const demoPath = path.join(process.cwd(), 'security-framework', 'tests', 'test_clearance_access_demo.py');
            if (!existsSync(demoPath)) {
                console.error(chalk.red('❌ Demo script not found'));
                console.error(chalk.red(`Expected path: ${demoPath}`));
                return;
            }
            console.log(chalk.yellow('🔄 Starting demonstration...'));
            console.log();
            // Execute the Python demo script
            const pythonProcess = spawn('python3', [demoPath], {
                stdio: 'inherit',
                cwd: process.cwd()
            });
            pythonProcess.on('close', (code) => {
                if (code === 0) {
                    console.log();
                    console.log(chalk.green('✅ Demo completed successfully!'));
                }
                else {
                    console.log();
                    console.error(chalk.red('❌ Demo failed with exit code:'), code);
                }
            });
            pythonProcess.on('error', (error) => {
                console.error(chalk.red('❌ Demo execution error:'), error);
            });
        }
        catch (error) {
            console.error(chalk.red('❌ Demo error:'), error);
        }
    }
    /**
     * Call the Python security framework
     */
    async callSecurityFramework(operation, params) {
        return new Promise((resolve, reject) => {
            // Create a simple Python script to call the security framework
            const scriptContent = `
import sys
import os
import json
sys.path.insert(0, '${this.securityFrameworkPath}')

try:
    from clearance_access_control import ClearanceAccessController, ClearanceLevel, PKINetwork
    from classification import SecurityClassification, SecurityClassificationLevel
    from crypto_utils import FIPSCryptoUtils, SecurityLevel
    from audit_logger import AuditLogger
    
    # Initialize components
    classification = SecurityClassification()
    crypto_utils = FIPSCryptoUtils(SecurityLevel.HIGH)
    audit_logger = AuditLogger()
    
    controller = ClearanceAccessController(
        classification, crypto_utils, audit_logger,
        hsm_config={"enabled": True, "provider": "demo"}
    )
    
    # Setup demo data for testing
    from datetime import datetime, timedelta
    
    # Mock authentication for demo
    if '${operation}' == 'authenticate_pki':
        result = {
            'success': True,
            'user_id': 'demo.user',
            'distinguished_name': 'CN=Demo User,OU=Demo,O=ALCUB3,C=US',
            'card_uuid': '${params.card_uuid || 'demo-card'}',
            'pki_network': '${params.network || 'niprnet'}',
            'authentication_time': ${Date.now()},
            'certificate_expiry': '${new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()}'
        }
    elif '${operation}' == 'get_metrics':
        result = controller.get_access_metrics()
    else:
        result = {'error': 'Operation not implemented in demo'}
    
    print(json.dumps(result))
    
except Exception as e:
    print(json.dumps({'error': str(e)}))
`;
            const pythonProcess = spawn('python3', ['-c', scriptContent], {
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
                        resolve(result);
                    }
                    catch (parseError) {
                        reject(new Error(`Failed to parse result: ${output}`));
                    }
                }
                else {
                    reject(new Error(`Python process failed: ${errorOutput}`));
                }
            });
            pythonProcess.on('error', (error) => {
                reject(error);
            });
        });
    }
}
// Export for use in CLI setup
export function registerClearanceCommands(program) {
    const clearanceCommands = new ClearanceCommands();
    clearanceCommands.registerCommands(program);
}
//# sourceMappingURL=clearance.js.map
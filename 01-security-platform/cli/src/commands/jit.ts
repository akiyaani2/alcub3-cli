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
import axios from 'axios';
import io, { Socket } from 'socket.io-client';
import Table from 'cli-table3';
import { formatDistanceToNow } from 'date-fns';

// API configuration
const API_BASE = process.env.ALCUB3_API_URL || 'http://localhost:8001/api/v1';
const SOCKET_URL = process.env.ALCUB3_SOCKET_URL || 'http://localhost:8001';

// Color scheme
const colors = {
  success: chalk.green,
  error: chalk.red,
  warning: chalk.yellow,
  info: chalk.cyan,
  highlight: chalk.magenta,
  dim: chalk.gray
};

// Interfaces
interface JITSession {
  sessionId: string;
  userId: string;
  grantedRole: string;
  expiresAt: string;
  timeRemaining: number;
  riskScore: number;
}

interface PendingApproval {
  approvalId: string;
  requestId: string;
  userId: string;
  requestedRole: string;
  justification: string;
  riskScore: number;
  createdAt: string;
}

/**
 * Create the JIT command
 */
export function createJITCommand(): Command {
  const jit = new Command('jit')
    .description('Just-in-Time privilege escalation management')
    .alias('privilege');

  // Request privilege escalation
  jit
    .command('request')
    .description('Request temporary privilege escalation')
    .option('-r, --role <role>', 'Requested role (e.g., admin, security_admin)')
    .option('-d, --duration <minutes>', 'Duration in minutes', '15')
    .option('-j, --justification <text>', 'Justification for request')
    .option('-c, --classification <level>', 'Classification level')
    .option('--resources <resources...>', 'Target resources')
    .option('--permissions <permissions...>', 'Specific permissions needed')
    .option('--interactive', 'Use interactive mode')
    .action(async (options) => {
      try {
        if (options.interactive || !options.role) {
          await requestPrivilegeInteractive();
        } else {
          await requestPrivilege(options);
        }
      } catch (error: any) {
        console.error(colors.error(`✗ Error: ${error.message}`));
        process.exit(1);
      }
    });

  // Check status
  jit
    .command('status [id]')
    .description('Check status of request or session')
    .option('-w, --watch', 'Watch for real-time updates')
    .action(async (id, options) => {
      try {
        if (id) {
          await checkStatus(id, options.watch);
        } else {
          await listActiveSessions();
        }
      } catch (error: any) {
        console.error(colors.error(`✗ Error: ${error.message}`));
        process.exit(1);
      }
    });

  // List active sessions
  jit
    .command('sessions')
    .description('List active privileged sessions')
    .option('-u, --user <userId>', 'Filter by user ID')
    .option('-w, --watch', 'Watch for real-time updates')
    .action(async (options) => {
      try {
        await listActiveSessions(options.user, options.watch);
      } catch (error: any) {
        console.error(colors.error(`✗ Error: ${error.message}`));
        process.exit(1);
      }
    });

  // Revoke session
  jit
    .command('revoke <sessionId>')
    .description('Revoke an active privileged session')
    .option('-r, --reason <reason>', 'Reason for revocation')
    .action(async (sessionId, options) => {
      try {
        await revokeSession(sessionId, options.reason);
      } catch (error: any) {
        console.error(colors.error(`✗ Error: ${error.message}`));
        process.exit(1);
      }
    });

  // Approve/deny requests (for approvers)
  jit
    .command('approve')
    .description('Review and approve/deny privilege requests')
    .option('-a, --approval-id <id>', 'Specific approval ID')
    .option('--approve', 'Approve the request')
    .option('--deny', 'Deny the request')
    .option('-c, --comments <text>', 'Comments for the decision')
    .action(async (options) => {
      try {
        if (options.approvalId && (options.approve || options.deny)) {
          await processApproval(
            options.approvalId,
            options.approve ? true : false,
            options.comments
          );
        } else {
          await reviewPendingApprovals();
        }
      } catch (error: any) {
        console.error(colors.error(`✗ Error: ${error.message}`));
        process.exit(1);
      }
    });

  // Show statistics (admin only)
  jit
    .command('stats')
    .description('Show JIT system statistics')
    .action(async () => {
      try {
        await showStatistics();
      } catch (error: any) {
        console.error(colors.error(`✗ Error: ${error.message}`));
        process.exit(1);
      }
    });

  return jit;
}

/**
 * Request privilege escalation interactively
 */
async function requestPrivilegeInteractive(): Promise<void> {
  console.log(colors.info('\n🔐 Just-in-Time Privilege Request\n'));

  const answers = await inquirer.prompt([
    {
      type: 'list',
      name: 'role',
      message: 'Select the role you need:',
      choices: [
        { name: 'Admin - Full system access', value: 'admin' },
        { name: 'Security Admin - Security configuration', value: 'security_admin' },
        { name: 'Operator - System operations', value: 'operator' },
        { name: 'Auditor - Read-only audit access', value: 'auditor' },
        { name: 'Custom - Specify custom role', value: 'custom' }
      ]
    },
    {
      type: 'input',
      name: 'customRole',
      message: 'Enter custom role name:',
      when: (answers) => answers.role === 'custom'
    },
    {
      type: 'number',
      name: 'duration',
      message: 'How long do you need access (minutes)?',
      default: 15,
      validate: (value) => {
        if (value < 5 || value > 480) {
          return 'Duration must be between 5 and 480 minutes';
        }
        return true;
      }
    },
    {
      type: 'editor',
      name: 'justification',
      message: 'Provide justification for this request:',
      validate: (value) => {
        if (value.length < 10) {
          return 'Justification must be at least 10 characters';
        }
        return true;
      }
    },
    {
      type: 'list',
      name: 'classification',
      message: 'Select classification level:',
      choices: ['UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'],
      default: 'UNCLASSIFIED'
    },
    {
      type: 'input',
      name: 'resources',
      message: 'Target resources (comma-separated, optional):',
      filter: (value) => value ? value.split(',').map((r: string) => r.trim()) : []
    },
    {
      type: 'confirm',
      name: 'confirm',
      message: 'Submit this privilege request?',
      default: true
    }
  ]);

  if (!answers.confirm) {
    console.log(colors.warning('\n✗ Request cancelled'));
    return;
  }

  const options = {
    role: answers.role === 'custom' ? answers.customRole : answers.role,
    duration: answers.duration,
    justification: answers.justification,
    classification: answers.classification,
    resources: answers.resources
  };

  await requestPrivilege(options);
}

/**
 * Request privilege escalation
 */
async function requestPrivilege(options: any): Promise<void> {
  const spinner = ora('Submitting privilege request...').start();

  try {
    // Get auth token (would come from auth system)
    const authToken = process.env.ALCUB3_AUTH_TOKEN || 'test-token';

    const response = await axios.post(
      `${API_BASE}/jit/request`,
      {
        role: options.role,
        duration: parseInt(options.duration),
        justification: options.justification,
        classification: options.classification,
        resources: options.resources,
        permissions: options.permissions,
        mfaVerified: true // In production, would trigger MFA
      },
      {
        headers: {
          'Authorization': `Bearer ${authToken}`,
          'Content-Type': 'application/json'
        }
      }
    );

    const result = response.data;

    if (result.status === 'approved') {
      spinner.succeed(colors.success(`✓ Privilege granted for ${options.duration} minutes`));
      console.log(colors.info(`\nSession ID: ${colors.highlight(result.sessionId)}`));
      console.log(colors.info(`Expires at: ${colors.highlight(new Date(result.expiresAt).toLocaleString())}`));
      console.log(colors.warning('\n⚠️  Remember: All actions are logged and monitored'));
      
      // Offer to monitor session
      const { monitor } = await inquirer.prompt([{
        type: 'confirm',
        name: 'monitor',
        message: 'Monitor this session for real-time updates?',
        default: false
      }]);

      if (monitor) {
        await monitorSession(result.sessionId);
      }
    } else if (result.status === 'pending') {
      spinner.info(colors.warning(`⏳ Approval required`));
      console.log(colors.info(`\nRequest ID: ${colors.highlight(result.requestId)}`));
      console.log(colors.info(`Approvers notified: ${result.approversNotified.join(', ')}`));
      console.log(colors.dim('\nYou will be notified when your request is processed'));
      
      // Offer to watch for updates
      const { watch } = await inquirer.prompt([{
        type: 'confirm',
        name: 'watch',
        message: 'Watch for approval updates?',
        default: true
      }]);

      if (watch) {
        await watchApproval(result.requestId);
      }
    } else {
      spinner.fail(colors.error(`✗ Request denied: ${result.reason}`));
    }

  } catch (error: any) {
    spinner.fail(colors.error(`✗ Failed to request privilege`));
    if (error.response?.data?.error) {
      console.error(colors.error(`Error: ${error.response.data.error}`));
    } else {
      console.error(colors.error(`Error: ${error.message}`));
    }
    throw error;
  }
}

/**
 * Check status of request or session
 */
async function checkStatus(id: string, watch: boolean = false): Promise<void> {
  const spinner = ora('Checking status...').start();

  try {
    const authToken = process.env.ALCUB3_AUTH_TOKEN || 'test-token';

    const response = await axios.get(
      `${API_BASE}/jit/status/${id}`,
      {
        headers: {
          'Authorization': `Bearer ${authToken}`
        }
      }
    );

    const status = response.data;
    spinner.stop();

    // Display status
    console.log(colors.info('\n📊 Status Information\n'));

    const table = new Table({
      style: { head: ['cyan'] }
    });

    if (status.sessionId) {
      // Session status
      table.push(
        ['Session ID', colors.highlight(status.sessionId)],
        ['User ID', status.userId],
        ['Role', colors.warning(status.grantedRole)],
        ['Active', status.isActive ? colors.success('Yes') : colors.error('No')],
        ['Expires', new Date(status.expiresAt).toLocaleString()],
        ['Time Remaining', formatTimeRemaining(status.timeRemaining)],
        ['Risk Score', getRiskScoreDisplay(status.riskScore)]
      );
    } else {
      // Approval status
      table.push(
        ['Request ID', colors.highlight(id)],
        ['Status', getStatusDisplay(status.status)],
        ['Created', new Date(status.createdAt).toLocaleString()]
      );

      if (status.approversNotified) {
        table.push(['Approvers', status.approversNotified.join(', ')]);
      }
    }

    console.log(table.toString());

    if (watch && status.isActive) {
      await monitorSession(id);
    }

  } catch (error: any) {
    spinner.fail(colors.error(`✗ Failed to get status`));
    if (error.response?.status === 404) {
      console.error(colors.error('Request or session not found'));
    } else {
      console.error(colors.error(`Error: ${error.message}`));
    }
    throw error;
  }
}

/**
 * List active sessions
 */
async function listActiveSessions(userId?: string, watch: boolean = false): Promise<void> {
  const spinner = ora('Fetching active sessions...').start();

  try {
    const authToken = process.env.ALCUB3_AUTH_TOKEN || 'test-token';

    const params = userId ? { userId } : {};
    const response = await axios.get(
      `${API_BASE}/jit/sessions`,
      {
        headers: {
          'Authorization': `Bearer ${authToken}`
        },
        params
      }
    );

    const { sessions, total } = response.data;
    spinner.stop();

    if (sessions.length === 0) {
      console.log(colors.info('\n📋 No active privileged sessions\n'));
      return;
    }

    console.log(colors.info(`\n📋 Active Privileged Sessions (${total})\n`));

    const table = new Table({
      head: ['Session ID', 'User', 'Role', 'Expires', 'Risk Score'],
      style: { head: ['cyan'] }
    });

    sessions.forEach((session: JITSession) => {
      table.push([
        colors.highlight(session.sessionId.substring(0, 8) + '...'),
        session.userId,
        colors.warning(session.grantedRole),
        formatDistanceToNow(new Date(session.expiresAt), { addSuffix: true }),
        getRiskScoreDisplay(session.riskScore)
      ]);
    });

    console.log(table.toString());

    if (watch) {
      console.log(colors.dim('\n👁️  Watching for updates... (Ctrl+C to stop)\n'));
      // Set up real-time monitoring
      const socket: Socket = io(`${SOCKET_URL}/jit`);
      
      socket.on('session-update', (update: any) => {
        console.log(colors.info(`\n[${new Date().toLocaleTimeString()}] Session update:`));
        console.log(update);
      });

      socket.on('session-revoked', (data: any) => {
        console.log(colors.error(`\n⚠️  Session ${data.sessionId} revoked: ${data.reason}`));
      });
    }

  } catch (error: any) {
    spinner.fail(colors.error(`✗ Failed to fetch sessions`));
    console.error(colors.error(`Error: ${error.message}`));
    throw error;
  }
}

/**
 * Revoke a session
 */
async function revokeSession(sessionId: string, reason?: string): Promise<void> {
  // Confirm revocation
  const { confirm } = await inquirer.prompt([{
    type: 'confirm',
    name: 'confirm',
    message: `Are you sure you want to revoke session ${sessionId}?`,
    default: false
  }]);

  if (!confirm) {
    console.log(colors.warning('\n✗ Revocation cancelled'));
    return;
  }

  const spinner = ora('Revoking session...').start();

  try {
    const authToken = process.env.ALCUB3_AUTH_TOKEN || 'test-token';

    const response = await axios.delete(
      `${API_BASE}/jit/session/${sessionId}`,
      {
        headers: {
          'Authorization': `Bearer ${authToken}`
        },
        data: {
          reason: reason || 'Manual revocation by user'
        }
      }
    );

    spinner.succeed(colors.success(`✓ Session revoked successfully`));
    console.log(colors.info(`\nReason: ${response.data.reason}`));

  } catch (error: any) {
    spinner.fail(colors.error(`✗ Failed to revoke session`));
    if (error.response?.status === 404) {
      console.error(colors.error('Session not found'));
    } else if (error.response?.status === 403) {
      console.error(colors.error('Not authorized to revoke this session'));
    } else {
      console.error(colors.error(`Error: ${error.message}`));
    }
    throw error;
  }
}

/**
 * Review pending approvals
 */
async function reviewPendingApprovals(): Promise<void> {
  const spinner = ora('Fetching pending approvals...').start();

  try {
    const authToken = process.env.ALCUB3_AUTH_TOKEN || 'test-token';

    const response = await axios.get(
      `${API_BASE}/jit/approvals/pending`,
      {
        headers: {
          'Authorization': `Bearer ${authToken}`
        }
      }
    );

    const { approvals, total } = response.data;
    spinner.stop();

    if (approvals.length === 0) {
      console.log(colors.info('\n✅ No pending approvals\n'));
      return;
    }

    console.log(colors.info(`\n📋 Pending Approvals (${total})\n`));

    // Process each approval interactively
    for (const approval of approvals) {
      displayApprovalDetails(approval);

      const { action } = await inquirer.prompt([{
        type: 'list',
        name: 'action',
        message: 'What would you like to do?',
        choices: [
          { name: '✅ Approve', value: 'approve' },
          { name: '❌ Deny', value: 'deny' },
          { name: '⏭️  Skip', value: 'skip' },
          { name: '🚪 Exit', value: 'exit' }
        ]
      }]);

      if (action === 'exit') {
        break;
      } else if (action === 'skip') {
        continue;
      }

      const { comments } = await inquirer.prompt([{
        type: 'input',
        name: 'comments',
        message: 'Comments (optional):'
      }]);

      await processApproval(approval.approvalId, action === 'approve', comments);
    }

  } catch (error: any) {
    spinner.fail(colors.error(`✗ Failed to fetch approvals`));
    console.error(colors.error(`Error: ${error.message}`));
    throw error;
  }
}

/**
 * Process an approval
 */
async function processApproval(approvalId: string, approved: boolean, comments?: string): Promise<void> {
  const spinner = ora('Processing approval...').start();

  try {
    const authToken = process.env.ALCUB3_AUTH_TOKEN || 'test-token';

    const response = await axios.post(
      `${API_BASE}/jit/approve`,
      {
        approvalId,
        approved,
        comments
      },
      {
        headers: {
          'Authorization': `Bearer ${authToken}`,
          'Content-Type': 'application/json'
        }
      }
    );

    if (approved) {
      spinner.succeed(colors.success(`✓ Request approved`));
    } else {
      spinner.succeed(colors.warning(`✓ Request denied`));
    }

  } catch (error: any) {
    spinner.fail(colors.error(`✗ Failed to process approval`));
    console.error(colors.error(`Error: ${error.message}`));
    throw error;
  }
}

/**
 * Show JIT statistics
 */
async function showStatistics(): Promise<void> {
  const spinner = ora('Fetching statistics...').start();

  try {
    const authToken = process.env.ALCUB3_AUTH_TOKEN || 'test-token';

    const response = await axios.get(
      `${API_BASE}/jit/stats`,
      {
        headers: {
          'Authorization': `Bearer ${authToken}`
        }
      }
    );

    const stats = response.data;
    spinner.stop();

    console.log(colors.info('\n📊 JIT System Statistics\n'));

    const table = new Table({
      style: { head: ['cyan'] }
    });

    table.push(
      ['Total Requests', colors.highlight(stats.totalRequests.toString())],
      ['Auto-Approved', colors.success(stats.autoApproved.toString())],
      ['Manually Approved', colors.info(stats.manuallyApproved.toString())],
      ['Denied', colors.error(stats.denied.toString())],
      ['Revoked', colors.warning(stats.revoked.toString())],
      ['Active Sessions', colors.highlight(stats.activeSessions.toString())],
      ['', ''],
      ['Approval Rate', `${stats.approvalRate.toFixed(1)}%`],
      ['Auto-Approval Rate', `${stats.autoApprovalRate.toFixed(1)}%`],
      ['Revocation Rate', `${stats.revocationRate.toFixed(1)}%`]
    );

    console.log(table.toString());

  } catch (error: any) {
    spinner.fail(colors.error(`✗ Failed to fetch statistics`));
    if (error.response?.status === 403) {
      console.error(colors.error('Security admin access required'));
    } else {
      console.error(colors.error(`Error: ${error.message}`));
    }
    throw error;
  }
}

/**
 * Monitor a session in real-time
 */
async function monitorSession(sessionId: string): Promise<void> {
  console.log(colors.dim('\n👁️  Monitoring session... (Ctrl+C to stop)\n'));

  const socket: Socket = io(`${SOCKET_URL}/jit`);

  socket.emit('monitor-session', sessionId);

  socket.on('session-update', (status: any) => {
    console.clear();
    console.log(colors.info('🔄 Session Status Update\n'));

    const table = new Table({
      style: { head: ['cyan'] }
    });

    table.push(
      ['Session ID', colors.highlight(status.sessionId)],
      ['Active', status.isActive ? colors.success('Yes') : colors.error('No')],
      ['Time Remaining', formatTimeRemaining(status.timeRemaining)],
      ['Risk Score', getRiskScoreDisplay(status.riskScore)]
    );

    console.log(table.toString());

    if (status.monitoringData) {
      console.log(colors.dim('\nMonitoring Data:'));
      console.log(JSON.stringify(status.monitoringData, null, 2));
    }
  });

  socket.on('session-revoked', (data: any) => {
    console.log(colors.error(`\n⚠️  Session revoked: ${data.reason}`));
    socket.disconnect();
    process.exit(0);
  });

  socket.on('error', (error: any) => {
    console.error(colors.error(`\n✗ WebSocket error: ${error.message}`));
  });
}

/**
 * Watch for approval updates
 */
async function watchApproval(requestId: string): Promise<void> {
  console.log(colors.dim('\n👁️  Watching for approval updates... (Ctrl+C to stop)\n'));

  const socket: Socket = io(`${SOCKET_URL}/jit`);

  socket.emit('subscribe-user', process.env.USER_ID || 'current-user');

  socket.on('approval-processed', (result: any) => {
    if (result.requestId === requestId) {
      if (result.status === 'approved') {
        console.log(colors.success('\n✅ Your request has been approved!'));
        console.log(colors.info(`Session ID: ${colors.highlight(result.sessionId)}`));
      } else {
        console.log(colors.error('\n❌ Your request has been denied'));
        console.log(colors.dim(`Reason: ${result.reason}`));
      }
      socket.disconnect();
      process.exit(0);
    }
  });

  socket.on('privilege-request-status', (update: any) => {
    if (update.requestId === requestId) {
      console.log(colors.info(`\n[${new Date().toLocaleTimeString()}] Status update: ${update.status}`));
    }
  });
}

/**
 * Display approval details
 */
function displayApprovalDetails(approval: PendingApproval): void {
  console.log(colors.warning('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'));
  
  const table = new Table({
    style: { head: ['cyan'] }
  });

  table.push(
    ['Approval ID', colors.highlight(approval.approvalId.substring(0, 8) + '...')],
    ['User', approval.userId],
    ['Requested Role', colors.warning(approval.requestedRole)],
    ['Risk Score', getRiskScoreDisplay(approval.riskScore)],
    ['Requested', formatDistanceToNow(new Date(approval.createdAt), { addSuffix: true })]
  );

  console.log(table.toString());
  console.log(colors.info('\nJustification:'));
  console.log(colors.dim(approval.justification));
}

/**
 * Format time remaining
 */
function formatTimeRemaining(seconds: number): string {
  if (seconds <= 0) {
    return colors.error('Expired');
  }

  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;

  if (minutes > 60) {
    const hours = Math.floor(minutes / 60);
    const remainingMinutes = minutes % 60;
    return colors.success(`${hours}h ${remainingMinutes}m`);
  }

  return colors.warning(`${minutes}m ${remainingSeconds}s`);
}

/**
 * Get risk score display
 */
function getRiskScoreDisplay(score: number): string {
  if (score >= 80) {
    return colors.error(`${score} (CRITICAL)`);
  } else if (score >= 60) {
    return colors.error(`${score} (HIGH)`);
  } else if (score >= 40) {
    return colors.warning(`${score} (MEDIUM)`);
  } else {
    return colors.success(`${score} (LOW)`);
  }
}

/**
 * Get status display
 */
function getStatusDisplay(status: string): string {
  switch (status) {
    case 'approved':
      return colors.success('Approved');
    case 'denied':
      return colors.error('Denied');
    case 'pending':
      return colors.warning('Pending');
    case 'expired':
      return colors.dim('Expired');
    case 'revoked':
      return colors.error('Revoked');
    default:
      return status;
  }
}
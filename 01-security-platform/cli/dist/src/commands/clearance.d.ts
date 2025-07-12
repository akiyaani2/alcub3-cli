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
import { Command } from 'commander';
export declare class ClearanceCommands {
    private securityFrameworkPath;
    constructor();
    /**
     * Register all clearance-related commands
     */
    registerCommands(program: Command): void;
    /**
     * Handle PKI/CAC authentication
     */
    private handleAuthenticate;
    /**
     * Handle security clearance validation
     */
    private handleValidateClearance;
    /**
     * Handle tool access authorization
     */
    private handleAuthorizeAccess;
    /**
     * Handle status display
     */
    private handleStatus;
    /**
     * Handle metrics display
     */
    private handleMetrics;
    /**
     * Handle demo execution
     */
    private handleDemo;
    /**
     * Call the Python security framework
     */
    private callSecurityFramework;
}
export declare function registerClearanceCommands(program: Command): void;

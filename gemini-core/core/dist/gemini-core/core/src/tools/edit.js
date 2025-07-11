/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */
import * as fs from 'fs';
import * as path from 'path';
import * as Diff from 'diff';
import { BaseTool, ToolConfirmationOutcome, } from './tools.js';
import { Type } from '@google/genai';
import { SchemaValidator } from '../utils/schemaValidator.js';
import { makeRelative, shortenPath } from '../utils/paths.js';
import { isNodeError } from '../utils/errors.js';
import { ApprovalMode } from '../config/config.js';
import { ensureCorrectEdit } from '../utils/editCorrector.js';
import { DEFAULT_DIFF_OPTIONS } from './diffOptions.js';
import { ReadFileTool } from './read-file.js';
/**
 * Implementation of the Edit tool logic
 */
export class EditTool extends BaseTool {
    config;
    static Name = 'replace';
    rootDirectory;
    /**
     * Creates a new instance of the EditLogic
     * @param rootDirectory Root directory to ground this tool in.
     */
    constructor(config) {
        super(EditTool.Name, 'Edit', `Replaces text within a file. By default, replaces a single occurrence, but can replace multiple occurrences when \`expected_replacements\` is specified. This tool requires providing significant context around the change to ensure precise targeting. Always use the ${ReadFileTool.Name} tool to examine the file's current content before attempting a text replacement.

      The user has the ability to modify the \`new_string\` content. If modified, this will be stated in the response.

Expectation for required parameters:
1. \`file_path\` MUST be an absolute path; otherwise an error will be thrown.
2. \`old_string\` MUST be the exact literal text to replace (including all whitespace, indentation, newlines, and surrounding code etc.).
3. \`new_string\` MUST be the exact literal text to replace \`old_string\` with (also including all whitespace, indentation, newlines, and surrounding code etc.). Ensure the resulting code is correct and idiomatic.
4. NEVER escape \`old_string\` or \`new_string\`, that would break the exact literal text requirement.
**Important:** If ANY of the above are not satisfied, the tool will fail. CRITICAL for \`old_string\`: Must uniquely identify the single instance to change. Include at least 3 lines of context BEFORE and AFTER the target text, matching whitespace and indentation precisely. If this string matches multiple locations, or does not match exactly, the tool will fail.
**Multiple replacements:** Set \`expected_replacements\` to the number of occurrences you want to replace. The tool will replace ALL occurrences that match \`old_string\` exactly. Ensure the number of replacements matches your expectation.`, {
            properties: {
                file_path: {
                    description: "The absolute path to the file to modify. Must start with '/'.",
                    type: Type.STRING,
                },
                old_string: {
                    description: 'The exact literal text to replace, preferably unescaped. For single replacements (default), include at least 3 lines of context BEFORE and AFTER the target text, matching whitespace and indentation precisely. For multiple replacements, specify expected_replacements parameter. If this string is not the exact literal text (i.e. you escaped it) or does not match exactly, the tool will fail.',
                    type: Type.STRING,
                },
                new_string: {
                    description: 'The exact literal text to replace `old_string` with, preferably unescaped. Provide the EXACT text. Ensure the resulting code is correct and idiomatic.',
                    type: Type.STRING,
                },
                expected_replacements: {
                    type: Type.NUMBER,
                    description: 'Number of replacements expected. Defaults to 1 if not specified. Use when you want to replace multiple occurrences.',
                    minimum: 1,
                },
            },
            required: ['file_path', 'old_string', 'new_string'],
            type: Type.OBJECT,
        });
        this.config = config;
        this.rootDirectory = path.resolve(this.config.getTargetDir());
    }
    /**
     * Checks if a path is within the root directory.
     * @param pathToCheck The absolute path to check.
     * @returns True if the path is within the root directory, false otherwise.
     */
    isWithinRoot(pathToCheck) {
        const normalizedPath = path.normalize(pathToCheck);
        const normalizedRoot = this.rootDirectory;
        const rootWithSep = normalizedRoot.endsWith(path.sep)
            ? normalizedRoot
            : normalizedRoot + path.sep;
        return (normalizedPath === normalizedRoot ||
            normalizedPath.startsWith(rootWithSep));
    }
    /**
     * Validates the parameters for the Edit tool
     * @param params Parameters to validate
     * @returns Error message string or null if valid
     */
    validateToolParams(params) {
        const errors = SchemaValidator.validate(this.schema.parameters, params);
        if (errors) {
            return errors;
        }
        if (!path.isAbsolute(params.file_path)) {
            return `File path must be absolute: ${params.file_path}`;
        }
        if (!this.isWithinRoot(params.file_path)) {
            return `File path must be within the root directory (${this.rootDirectory}): ${params.file_path}`;
        }
        return null;
    }
    _applyReplacement(currentContent, oldString, newString, isNewFile) {
        if (isNewFile) {
            return newString;
        }
        if (currentContent === null) {
            // Should not happen if not a new file, but defensively return empty or newString if oldString is also empty
            return oldString === '' ? newString : '';
        }
        // If oldString is empty and it's not a new file, do not modify the content.
        if (oldString === '' && !isNewFile) {
            return currentContent;
        }
        return currentContent.replaceAll(oldString, newString);
    }
    /**
     * Calculates the potential outcome of an edit operation.
     * @param params Parameters for the edit operation
     * @returns An object describing the potential edit outcome
     * @throws File system errors if reading the file fails unexpectedly (e.g., permissions)
     */
    async calculateEdit(params, abortSignal) {
        const expectedReplacements = params.expected_replacements ?? 1;
        let currentContent = null;
        let fileExists = false;
        let isNewFile = false;
        let finalNewString = params.new_string;
        let finalOldString = params.old_string;
        let occurrences = 0;
        let error = undefined;
        try {
            currentContent = fs.readFileSync(params.file_path, 'utf8');
            // Normalize line endings to LF for consistent processing.
            currentContent = currentContent.replace(/\r\n/g, '\n');
            fileExists = true;
        }
        catch (err) {
            if (!isNodeError(err) || err.code !== 'ENOENT') {
                // Rethrow unexpected FS errors (permissions, etc.)
                throw err;
            }
            fileExists = false;
        }
        if (params.old_string === '' && !fileExists) {
            // Creating a new file
            isNewFile = true;
        }
        else if (!fileExists) {
            // Trying to edit a non-existent file (and old_string is not empty)
            error = {
                display: `File not found. Cannot apply edit. Use an empty old_string to create a new file.`,
                raw: `File not found: ${params.file_path}`,
            };
        }
        else if (currentContent !== null) {
            // Editing an existing file
            const correctedEdit = await ensureCorrectEdit(params.file_path, currentContent, params, this.config.getGeminiClient(), abortSignal);
            finalOldString = correctedEdit.params.old_string;
            finalNewString = correctedEdit.params.new_string;
            occurrences = correctedEdit.occurrences;
            if (params.old_string === '') {
                // Error: Trying to create a file that already exists
                error = {
                    display: `Failed to edit. Attempted to create a file that already exists.`,
                    raw: `File already exists, cannot create: ${params.file_path}`,
                };
            }
            else if (occurrences === 0) {
                error = {
                    display: `Failed to edit, could not find the string to replace.`,
                    raw: `Failed to edit, 0 occurrences found for old_string in ${params.file_path}. No edits made. The exact text in old_string was not found. Ensure you're not escaping content incorrectly and check whitespace, indentation, and context. Use ${ReadFileTool.Name} tool to verify.`,
                };
            }
            else if (occurrences !== expectedReplacements) {
                const occurenceTerm = expectedReplacements === 1 ? 'occurrence' : 'occurrences';
                error = {
                    display: `Failed to edit, expected ${expectedReplacements} ${occurenceTerm} but found ${occurrences}.`,
                    raw: `Failed to edit, Expected ${expectedReplacements} ${occurenceTerm} but found ${occurrences} for old_string in file: ${params.file_path}`,
                };
            }
        }
        else {
            // Should not happen if fileExists and no exception was thrown, but defensively:
            error = {
                display: `Failed to read content of file.`,
                raw: `Failed to read content of existing file: ${params.file_path}`,
            };
        }
        const newContent = this._applyReplacement(currentContent, finalOldString, finalNewString, isNewFile);
        return {
            currentContent,
            newContent,
            occurrences,
            error,
            isNewFile,
        };
    }
    /**
     * Handles the confirmation prompt for the Edit tool in the CLI.
     * It needs to calculate the diff to show the user.
     */
    async shouldConfirmExecute(params, abortSignal) {
        if (this.config.getApprovalMode() === ApprovalMode.AUTO_EDIT) {
            return false;
        }
        const validationError = this.validateToolParams(params);
        if (validationError) {
            console.error(`[EditTool Wrapper] Attempted confirmation with invalid parameters: ${validationError}`);
            return false;
        }
        let editData;
        try {
            editData = await this.calculateEdit(params, abortSignal);
        }
        catch (error) {
            const errorMsg = error instanceof Error ? error.message : String(error);
            console.log(`Error preparing edit: ${errorMsg}`);
            return false;
        }
        if (editData.error) {
            console.log(`Error: ${editData.error.display}`);
            return false;
        }
        const fileName = path.basename(params.file_path);
        const fileDiff = Diff.createPatch(fileName, editData.currentContent ?? '', editData.newContent, 'Current', 'Proposed', DEFAULT_DIFF_OPTIONS);
        const confirmationDetails = {
            type: 'edit',
            title: `Confirm Edit: ${shortenPath(makeRelative(params.file_path, this.rootDirectory))}`,
            fileName,
            fileDiff,
            onConfirm: async (outcome) => {
                if (outcome === ToolConfirmationOutcome.ProceedAlways) {
                    this.config.setApprovalMode(ApprovalMode.AUTO_EDIT);
                }
            },
        };
        return confirmationDetails;
    }
    getDescription(params) {
        if (!params.file_path || !params.old_string || !params.new_string) {
            return `Model did not provide valid parameters for edit tool`;
        }
        const relativePath = makeRelative(params.file_path, this.rootDirectory);
        if (params.old_string === '') {
            return `Create ${shortenPath(relativePath)}`;
        }
        const oldStringSnippet = params.old_string.split('\n')[0].substring(0, 30) +
            (params.old_string.length > 30 ? '...' : '');
        const newStringSnippet = params.new_string.split('\n')[0].substring(0, 30) +
            (params.new_string.length > 30 ? '...' : '');
        if (params.old_string === params.new_string) {
            return `No file changes to ${shortenPath(relativePath)}`;
        }
        return `${shortenPath(relativePath)}: ${oldStringSnippet} => ${newStringSnippet}`;
    }
    /**
     * Executes the edit operation with the given parameters.
     * @param params Parameters for the edit operation
     * @returns Result of the edit operation
     */
    async execute(params, signal) {
        const validationError = this.validateToolParams(params);
        if (validationError) {
            return {
                llmContent: `Error: Invalid parameters provided. Reason: ${validationError}`,
                returnDisplay: `Error: ${validationError}`,
            };
        }
        let editData;
        try {
            editData = await this.calculateEdit(params, signal);
        }
        catch (error) {
            const errorMsg = error instanceof Error ? error.message : String(error);
            return {
                llmContent: `Error preparing edit: ${errorMsg}`,
                returnDisplay: `Error preparing edit: ${errorMsg}`,
            };
        }
        if (editData.error) {
            return {
                llmContent: editData.error.raw,
                returnDisplay: `Error: ${editData.error.display}`,
            };
        }
        try {
            this.ensureParentDirectoriesExist(params.file_path);
            fs.writeFileSync(params.file_path, editData.newContent, 'utf8');
            let displayResult;
            if (editData.isNewFile) {
                displayResult = `Created ${shortenPath(makeRelative(params.file_path, this.rootDirectory))}`;
            }
            else {
                // Generate diff for display, even though core logic doesn't technically need it
                // The CLI wrapper will use this part of the ToolResult
                const fileName = path.basename(params.file_path);
                const fileDiff = Diff.createPatch(fileName, editData.currentContent ?? '', // Should not be null here if not isNewFile
                editData.newContent, 'Current', 'Proposed', DEFAULT_DIFF_OPTIONS);
                displayResult = { fileDiff, fileName };
            }
            const llmSuccessMessageParts = [
                editData.isNewFile
                    ? `Created new file: ${params.file_path} with provided content.`
                    : `Successfully modified file: ${params.file_path} (${editData.occurrences} replacements).`,
            ];
            if (params.modified_by_user) {
                llmSuccessMessageParts.push(`User modified the \`new_string\` content to be: ${params.new_string}.`);
            }
            return {
                llmContent: llmSuccessMessageParts.join(' '),
                returnDisplay: displayResult,
            };
        }
        catch (error) {
            const errorMsg = error instanceof Error ? error.message : String(error);
            return {
                llmContent: `Error executing edit: ${errorMsg}`,
                returnDisplay: `Error writing file: ${errorMsg}`,
            };
        }
    }
    /**
     * Creates parent directories if they don't exist
     */
    ensureParentDirectoriesExist(filePath) {
        const dirName = path.dirname(filePath);
        if (!fs.existsSync(dirName)) {
            fs.mkdirSync(dirName, { recursive: true });
        }
    }
    getModifyContext(_) {
        return {
            getFilePath: (params) => params.file_path,
            getCurrentContent: async (params) => {
                try {
                    return fs.readFileSync(params.file_path, 'utf8');
                }
                catch (err) {
                    if (!isNodeError(err) || err.code !== 'ENOENT')
                        throw err;
                    return '';
                }
            },
            getProposedContent: async (params) => {
                try {
                    const currentContent = fs.readFileSync(params.file_path, 'utf8');
                    return this._applyReplacement(currentContent, params.old_string, params.new_string, params.old_string === '' && currentContent === '');
                }
                catch (err) {
                    if (!isNodeError(err) || err.code !== 'ENOENT')
                        throw err;
                    return '';
                }
            },
            createUpdatedParams: (oldContent, modifiedProposedContent, originalParams) => ({
                ...originalParams,
                old_string: oldContent,
                new_string: modifiedProposedContent,
                modified_by_user: true,
            }),
        };
    }
}
//# sourceMappingURL=edit.js.map
#!/usr/bin/env node

const fs = require('fs');

function validateTasks(filename) {
  const data = JSON.parse(fs.readFileSync(filename, 'utf8'));
  const errors = [];
  const warnings = [];
  
  // Check for required structure
  if (!data.master || !data.master.tasks) {
    errors.push('Missing master.tasks structure');
    return { errors, warnings };
  }
  
  const tasks = data.master.tasks;
  const validIds = new Set();
  
  // Validate each task
  tasks.forEach((task, index) => {
    // Check required fields
    if (task.id === undefined) errors.push(`Task at index ${index} missing id`);
    if (!task.title) errors.push(`Task ${task.id} missing title`);
    if (!task.status) errors.push(`Task ${task.id} missing status`);
    if (!task.priority) errors.push(`Task ${task.id} missing priority`);
    
    // Check for duplicate IDs
    if (validIds.has(task.id)) {
      errors.push(`Duplicate task ID: ${task.id}`);
    }
    validIds.add(task.id);
    
    // Validate dependencies
    if (task.dependencies && Array.isArray(task.dependencies)) {
      task.dependencies.forEach(dep => {
        // Special case: PILLAR 0 (Market & Business) can depend on other PILLARs
        if (task.id === 0) {
          // This is expected - Market & Business depends on technical pillars
        } else if (dep >= task.id) {
          warnings.push(`Task ${task.id} depends on task ${dep} which comes after it`);
        }
      });
    }
    
    // Validate subtasks
    if (task.subtasks && Array.isArray(task.subtasks)) {
      const subtaskIds = new Set();
      task.subtasks.forEach((subtask, subIndex) => {
        if (!subtask.id) errors.push(`Subtask at index ${subIndex} in task ${task.id} missing id`);
        if (!subtask.title) errors.push(`Subtask ${subtask.id} in task ${task.id} missing title`);
        if (!subtask.status) warnings.push(`Subtask ${subtask.id} in task ${task.id} missing status`);
        
        if (subtaskIds.has(subtask.id)) {
          errors.push(`Duplicate subtask ID ${subtask.id} in task ${task.id}`);
        }
        subtaskIds.add(subtask.id);
      });
    }
  });
  
  // Check expected PILLARs exist
  const expectedIds = [0, 1, 2, 3, 4, 5, 7];
  expectedIds.forEach(id => {
    if (!tasks.find(t => t.id === id)) {
      errors.push(`Missing expected PILLAR ${id}`);
    }
  });
  
  return { errors, warnings };
}

// Run validation
console.log('🔍 Validating task structure...\n');
const result = validateTasks('tasks_unified.json');

if (result.errors.length > 0) {
  console.log('❌ Errors found:');
  result.errors.forEach(err => console.log('  - ' + err));
}

if (result.warnings.length > 0) {
  console.log('\n⚠️  Warnings:');
  result.warnings.forEach(warn => console.log('  - ' + warn));
}

if (result.errors.length === 0 && result.warnings.length === 0) {
  console.log('✅ Task structure is valid!');
}

console.log(`\n📊 Summary: ${result.errors.length} errors, ${result.warnings.length} warnings`);
process.exit(result.errors.length > 0 ? 1 : 0);

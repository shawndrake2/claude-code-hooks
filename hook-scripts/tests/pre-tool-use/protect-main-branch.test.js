#!/usr/bin/env node
/**
 * Tests for protect-main-branch.js
 *
 * Run: node --test hook-scripts/tests/pre-tool-use/protect-main-branch.test.js
 * Or:  npm test
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('node:child_process');
const path = require('node:path');

const { PATTERNS, PROTECTED_BRANCHES, checkCommand } = require('../../pre-tool-use/protect-main-branch.js');

const SCRIPT_PATH = path.join(__dirname, '../../pre-tool-use/protect-main-branch.js');

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

function shouldBlock(cmd, expectedId = null, branch = null) {
  const result = checkCommand(cmd, branch);
  assert.strictEqual(result.blocked, true, `Expected BLOCKED but was ALLOWED: ${cmd}`);
  if (expectedId) {
    assert.strictEqual(result.pattern.id, expectedId, `Expected pattern '${expectedId}' but got '${result.pattern.id}'`);
  }
}

function shouldAllow(cmd, branch = null) {
  const result = checkCommand(cmd, branch);
  assert.strictEqual(result.blocked, false, `Expected ALLOWED but was BLOCKED by '${result.pattern?.id}': ${cmd}`);
}

function runHook(command) {
  return new Promise((resolve, reject) => {
    const child = spawn('node', [SCRIPT_PATH]);
    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (data) => { stdout += data; });
    child.stderr.on('data', (data) => { stderr += data; });

    child.on('close', (code) => {
      try {
        const output = JSON.parse(stdout.trim());
        resolve({ code, output, stderr });
      } catch (e) {
        reject(new Error(`Failed to parse output: ${stdout}`));
      }
    });

    const hookInput = JSON.stringify({
      tool_name: 'Bash',
      tool_input: { command },
      session_id: 'test-session',
      cwd: '/tmp',
      permission_mode: 'default'
    });
    child.stdin.write(hookInput);
    child.stdin.end();
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit Tests - checkCommand function
// ─────────────────────────────────────────────────────────────────────────────

describe('Unit: checkCommand()', () => {
  describe('Dangerous pushes (always blocked)', () => {
    it('blocks git push --force', () => shouldBlock('git push --force origin feature', 'force-push'));
    it('blocks git push -f', () => shouldBlock('git push -f origin feature', 'force-push'));
    it('blocks git push --force to main', () => shouldBlock('git push --force origin main', 'force-push'));
    it('blocks git push to main', () => shouldBlock('git push origin main', 'push-main'));
    it('blocks git push main', () => shouldBlock('git push main', 'push-main'));
    it('blocks git push to master', () => shouldBlock('git push origin master', 'push-master'));
    it('blocks git push master', () => shouldBlock('git push master', 'push-master'));
  });

  describe('Direct changes on protected branches', () => {
    it('blocks git commit on main', () => shouldBlock('git commit -m "fix"', 'commit-on-protected', 'main'));
    it('blocks git commit on master', () => shouldBlock('git commit -m "fix"', 'commit-on-protected', 'master'));
    it('blocks git commit --amend on main', () => shouldBlock('git commit --amend', 'commit-on-protected', 'main'));
    it('blocks git push on main', () => shouldBlock('git push origin feature', 'push-on-protected', 'main'));
    it('blocks git push on master', () => shouldBlock('git push origin feature', 'push-on-protected', 'master'));
  });

  describe('Branch-only rules allow on feature branches', () => {
    it('allows git commit on feature branch', () => shouldAllow('git commit -m "fix"', 'feature-branch'));
    it('allows git commit on develop', () => shouldAllow('git commit -m "fix"', 'develop'));
    it('allows git push on feature branch', () => shouldAllow('git push origin feature', 'feature-branch'));
  });

  describe('PR merge blocking', () => {
    it('blocks gh pr merge', () => shouldBlock('gh pr merge', 'gh-pr-merge'));
    it('blocks gh pr merge with number', () => shouldBlock('gh pr merge 123', 'gh-pr-merge'));
    it('blocks gh pr merge with flags', () => shouldBlock('gh pr merge --squash', 'gh-pr-merge'));
    it('blocks gh pr merge --rebase', () => shouldBlock('gh pr merge --rebase 42', 'gh-pr-merge'));
  });

  describe('Safe commands', () => {
    const safeCommands = [
      'git status',
      'git log --oneline',
      'git diff',
      'git pull origin main',
      'git fetch --all',
      'git checkout -b new-branch',
      'git branch -d old-branch',
      'git stash',
      'git rebase main',
      'gh pr create --title "feat: new thing"',
      'gh pr list',
      'gh pr view 123',
      'npm install',
      'ls -la',
    ];
    for (const cmd of safeCommands) {
      it(`allows: ${cmd}`, () => shouldAllow(cmd, 'feature-branch'));
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Integration Tests - actual stdin/stdout flow
// ─────────────────────────────────────────────────────────────────────────────

describe('Integration: stdin/stdout hook flow', () => {
  it('returns deny for git push to main', async () => {
    const { code, output } = await runHook('git push origin main');
    assert.strictEqual(code, 0);
    assert.strictEqual(output.hookSpecificOutput?.permissionDecision, 'deny');
    assert.ok(output.hookSpecificOutput?.permissionDecisionReason.includes('push-main'));
  });

  it('returns deny for force push', async () => {
    const { code, output } = await runHook('git push --force origin feature');
    assert.strictEqual(code, 0);
    assert.strictEqual(output.hookSpecificOutput?.permissionDecision, 'deny');
    assert.ok(output.hookSpecificOutput?.permissionDecisionReason.includes('force-push'));
  });

  it('returns deny for gh pr merge', async () => {
    const { code, output } = await runHook('gh pr merge 123');
    assert.strictEqual(code, 0);
    assert.strictEqual(output.hookSpecificOutput?.permissionDecision, 'deny');
    assert.ok(output.hookSpecificOutput?.permissionDecisionReason.includes('gh-pr-merge'));
  });

  it('returns empty object for safe command', async () => {
    const { code, output } = await runHook('git status');
    assert.strictEqual(code, 0);
    assert.deepStrictEqual(output, {});
  });

  it('returns empty object for non-Bash tool', async () => {
    const child = spawn('node', [SCRIPT_PATH]);
    let stdout = '';

    const result = await new Promise((resolve) => {
      child.stdout.on('data', (data) => { stdout += data; });
      child.on('close', (code) => {
        resolve({ code, output: JSON.parse(stdout.trim()) });
      });

      child.stdin.write(JSON.stringify({
        tool_name: 'Read',
        tool_input: { file_path: '/etc/passwd' }
      }));
      child.stdin.end();
    });

    assert.deepStrictEqual(result.output, {});
  });

  it('includes emoji in deny reason', async () => {
    const { output } = await runHook('git push origin main');
    const reason = output.hookSpecificOutput?.permissionDecisionReason;
    assert.ok(reason.includes('⛔'));
  });

  it('returns empty object for invalid JSON input', async () => {
    const child = spawn('node', [SCRIPT_PATH]);
    let stdout = '';

    const result = await new Promise((resolve) => {
      child.stdout.on('data', (data) => { stdout += data; });
      child.on('close', (code) => {
        resolve({ code, output: JSON.parse(stdout.trim()) });
      });

      child.stdin.write('not json');
      child.stdin.end();
    });

    assert.deepStrictEqual(result.output, {});
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Config Tests - verify PATTERNS structure
// ─────────────────────────────────────────────────────────────────────────────

describe('Config: PATTERNS structure', () => {
  it('has unique id for each pattern', () => {
    const ids = PATTERNS.map(p => p.id);
    const unique = [...new Set(ids)];
    assert.strictEqual(ids.length, unique.length, 'Duplicate pattern IDs found');
  });

  it('has regex and reason for each pattern', () => {
    for (const p of PATTERNS) {
      assert.ok(p.regex instanceof RegExp, `Pattern ${p.id} missing regex`);
      assert.ok(typeof p.reason === 'string' && p.reason.length > 0, `Pattern ${p.id} missing reason`);
    }
  });

  it('branchOnly patterns have {branch} placeholder in reason', () => {
    for (const p of PATTERNS.filter(p => p.branchOnly)) {
      assert.ok(p.reason.includes('{branch}'), `Pattern ${p.id} is branchOnly but reason lacks {branch} placeholder`);
    }
  });

  it('non-branchOnly patterns do not have {branch} placeholder', () => {
    for (const p of PATTERNS.filter(p => !p.branchOnly)) {
      assert.ok(!p.reason.includes('{branch}'), `Pattern ${p.id} is not branchOnly but reason has {branch} placeholder`);
    }
  });

  it('PROTECTED_BRANCHES includes main and master', () => {
    assert.ok(PROTECTED_BRANCHES.includes('main'));
    assert.ok(PROTECTED_BRANCHES.includes('master'));
  });
});

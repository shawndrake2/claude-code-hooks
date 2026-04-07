#!/usr/bin/env node
/**
 * Branch Protection - PreToolUse Hook for Bash
 * Blocks destructive git operations on main/master branches.
 *
 * Setup in .claude/settings.json:
 * {
 *   "hooks": {
 *     "PreToolUse": [{
 *       "matcher": "Bash",
 *       "hooks": [{ "type": "command", "command": "node ~/.claude/hooks/protect-main-branch.js" }]
 *     }]
 *   }
 * }
 */

const { execFileSync } = require('child_process');

const PROTECTED_BRANCHES = ['main', 'master'];

const PATTERNS = [
    // Block dangerous push variants regardless of branch
    { id: 'force-push',          regex: /\bgit\s+push\b.*(?:--force|-f)\b/,            reason: 'Force-pushing is not allowed' },
    { id: 'push-main',           regex: /\bgit\s+push\b.*\bmain\b/,                    reason: 'Pushing to main is not allowed' },
    { id: 'push-master',         regex: /\bgit\s+push\b.*\bmaster\b/,                  reason: 'Pushing to master is not allowed' },

    // Block direct changes when on a protected branch
    { id: 'commit-on-protected', regex: /\bgit\s+commit\b/,                            reason: 'Committing directly on {branch} is not allowed', branchOnly: true },
    { id: 'push-on-protected',   regex: /\bgit\s+push\b/,                              reason: 'Pushing from {branch} is not allowed', branchOnly: true },

    // Block merging PRs directly
    { id: 'gh-pr-merge',         regex: /\bgh\s+pr\s+merge\b/,                         reason: 'Merging PRs via gh CLI is not allowed' },
];

function getCurrentBranch() {
    try {
        return execFileSync('git', ['branch', '--show-current'], { encoding: 'utf-8' }).trim();
    } catch {
        return '';
    }
}

function checkCommand(cmd, branch = null) {
    for (const p of PATTERNS) {
        if (!p.regex.test(cmd)) continue;

        if (p.branchOnly) {
            if (!branch) branch = getCurrentBranch();
            if (!PROTECTED_BRANCHES.includes(branch)) continue;
        }

        const reason = p.reason.replace('{branch}', branch || '');
        return { blocked: true, pattern: p, reason };
    }

    return { blocked: false };
}

async function main() {
    let input = '';
    for await (const chunk of process.stdin) input += chunk;

    try {
        const data = JSON.parse(input);
        if (data.tool_name !== 'Bash') return console.log('{}');

        const cmd = data.tool_input?.command || '';
        const result = checkCommand(cmd);

        if (result.blocked) {
            return console.log(JSON.stringify({
                hookSpecificOutput: {
                    hookEventName: 'PreToolUse',
                    permissionDecision: 'deny',
                    permissionDecisionReason: `⛔ [${result.pattern.id}] ${result.reason}`
                }
            }));
        }

        console.log('{}');
    } catch (e) {
        console.log('{}');
    }
}

if (require.main === module) {
    main();
} else {
    module.exports = { PATTERNS, PROTECTED_BRANCHES, checkCommand };
}

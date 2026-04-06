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
 *       "hooks": [{ "type": "command", "command": "node ~/.claude/hooks/branch-protection.js" }]
 *     }]
 *   }
 * }
 */

const { execFileSync } = require('child_process');

const PROTECTED_BRANCHES = ['main', 'master'];

const PATTERNS = [
    { id: 'push-main',         regex: /\bgit\s+push\b.*\bmain\b/,                     reason: 'Pushing to main is not allowed' },
    { id: 'push-master',       regex: /\bgit\s+push\b.*\bmaster\b/,                   reason: 'Pushing to master is not allowed' },
    { id: 'force-push',        regex: /\bgit\s+push\b.*(?:--force|-f)\b/,             reason: 'Force-pushing is not allowed' },
    { id: 'commit-on-protected', regex: /\bgit\s+commit\b/,                           reason: 'Committing directly on {branch} is not allowed', branchOnly: true },
    { id: 'gh-pr-merge',       regex: /\bgh\s+pr\s+merge\b/,                          reason: 'Merging PRs via gh CLI is not allowed' },
];

function getCurrentBranch() {
    try {
        return execFileSync('git', ['branch', '--show-current'], { encoding: 'utf-8' }).trim();
    } catch {
        return '';
    }
}

async function main() {
    let input = '';
    for await (const chunk of process.stdin) input += chunk;

    try {
        const data = JSON.parse(input);
        if (data.tool_name !== 'Bash') return console.log('{}');

        const cmd = data.tool_input?.command || '';
        let branch = null;

        for (const p of PATTERNS) {
            if (!p.regex.test(cmd)) continue;

            if (p.branchOnly) {
                if (!branch) branch = getCurrentBranch();
                if (!PROTECTED_BRANCHES.includes(branch)) continue;
            }

            const reason = p.reason.replace('{branch}', branch || '');
            return console.log(JSON.stringify({
                hookSpecificOutput: {
                    hookEventName: 'PreToolUse',
                    permissionDecision: 'deny',
                    permissionDecisionReason: `⛔ [${p.id}] ${reason}`
                }
            }));
        }

        console.log('{}');
    } catch (e) {
        console.log('{}');
    }
}

main();

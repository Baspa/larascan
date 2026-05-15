<?php

declare(strict_types=1);

use Baspa\Larascan\Support\AgentDetector;

/**
 * The env vars laravel/agent-detector consults (plus our manual override).
 * We snapshot and restore them around each test so that running under e.g.
 * Claude Code (which sets CLAUDECODE=1) doesn't bleed into the assertions
 * below.
 */
$AGENT_VARS = [
    'AI_AGENT',
    'CLAUDECODE',
    'CLAUDE_CODE',
    'CLAUDE_CODE_IS_COWORK',
    'CURSOR_AGENT',
    'GEMINI_CLI',
    'CODEX_SANDBOX',
    'CODEX_CI',
    'CODEX_THREAD_ID',
    'AUGMENT_AGENT',
    'OPENCODE_CLIENT',
    'OPENCODE',
    'AMP_CURRENT_THREAD_ID',
    'REPL_ID',
    'COPILOT_MODEL',
    'COPILOT_ALLOW_ALL',
    'COPILOT_GITHUB_TOKEN',
    'COPILOT_CLI',
    'ANTIGRAVITY_AGENT',
    'PI_CODING_AGENT',
    'KIRO_AGENT_PATH',
    'LARASCAN_AGENT_MODE',
];

beforeEach(function () use ($AGENT_VARS) {
    $this->originalAgentEnv = [];
    foreach ($AGENT_VARS as $var) {
        $this->originalAgentEnv[$var] = getenv($var);
        putenv($var);
    }
});

afterEach(function () use ($AGENT_VARS) {
    foreach ($AGENT_VARS as $var) {
        $original = $this->originalAgentEnv[$var] ?? false;
        if ($original === false) {
            putenv($var);
        } else {
            putenv("{$var}={$original}");
        }
    }
});

it('returns false when no agent env var is set', function () {
    expect(AgentDetector::isAgentRun())->toBeFalse();
});

it('returns true when CLAUDECODE is set', function () {
    putenv('CLAUDECODE=1');
    expect(AgentDetector::isAgentRun())->toBeTrue();
});

it('returns true when LARASCAN_AGENT_MODE is set (manual override)', function () {
    putenv('LARASCAN_AGENT_MODE=1');
    expect(AgentDetector::isAgentRun())->toBeTrue();
});

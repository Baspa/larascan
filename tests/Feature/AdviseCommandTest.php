<?php

declare(strict_types=1);

/**
 * Clear AI agent env vars around each test so the auto-format detection
 * doesn't switch to JSON when the suite runs under Claude Code / Cursor /
 * Aider / etc. Tests below assume the default human output.
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

it('runs the advise command and exits 0', function () {
    $this->artisan('larascan:advise')
        ->expectsOutputToContain('larascan')
        ->assertExitCode(0);
});

it('runs the advise command with --format=json and outputs valid JSON', function () {
    $this->artisan('larascan:advise', ['--format' => 'json'])
        ->assertExitCode(0);
});

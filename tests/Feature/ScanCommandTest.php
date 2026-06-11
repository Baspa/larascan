<?php

declare(strict_types=1);
use Illuminate\Support\Facades\Artisan;

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

it('runs the larascan command and shows the report', function () {
    // Make the testbench app look like a clean prod deploy so no shipped
    // check fires above the default fail_on=high threshold.
    config()->set('app.key', 'base64:fJjK9p8wQYJxhmKQYr8MwhYrnX1z3vKzpW9rh4vF8rA=');
    config()->set('app.env', 'production');
    config()->set('app.debug', false);
    config()->set('session.secure', true);
    config()->set('session.http_only', true);
    config()->set('session.same_site', 'lax');
    config()->set('session.encrypt', true);
    config()->set('session.lifetime', 120);
    $checks = config('larascan.checks', []);
    $checks['headers.hsts'] = ['enabled' => false];
    $checks['headers.x-content-type-options'] = ['enabled' => false];
    $checks['headers.x-frame-options'] = ['enabled' => false];
    $checks['php.display-errors'] = ['enabled' => false];
    $checks['csrf.middleware-disabled'] = ['enabled' => false];
    $checks['injection.host-header'] = ['enabled' => false];
    config()->set('larascan.checks', $checks);

    $this->artisan('larascan')
        ->expectsOutputToContain('larascan')
        ->expectsOutputToContain('Report Card')
        ->assertExitCode(0);
});

it('honors --fail-on for exit code', function () {
    // With AppKeyCheck registered, testbench's empty app.key would yield a
    // Critical finding. Set a key so the scan runs cleanly.
    config()->set('app.key', 'base64:fJjK9p8wQYJxhmKQYr8MwhYrnX1z3vKzpW9rh4vF8rA=');
    config()->set('session.secure', true);
    config()->set('session.http_only', true);
    config()->set('session.same_site', 'lax');
    config()->set('session.encrypt', true);
    config()->set('session.lifetime', 120);
    $checks = config('larascan.checks', []);
    $checks['csrf.middleware-disabled'] = ['enabled' => false];
    config()->set('larascan.checks', $checks);

    $this->artisan('larascan --fail-on=critical')->assertExitCode(0);
});

it('filters checks via --check pattern', function () {
    $this->artisan('larascan --check=does.not.exist')
        ->expectsOutputToContain('larascan')
        ->assertExitCode(0);
});

it('exits 2 on invalid --fail-on value', function () {
    $this->artisan('larascan --fail-on=bogus')
        ->expectsOutputToContain('Invalid --fail-on value: bogus')
        ->assertExitCode(2);
});

it('exits 2 on unknown --category', function () {
    $this->artisan('larascan --category=nonsense')
        ->expectsOutputToContain('Unknown category: nonsense')
        ->assertExitCode(2);
});

it('accepts a valid --category filter', function () {
    // Same clean-prod setup as the smoke test above.
    config()->set('app.key', 'base64:fJjK9p8wQYJxhmKQYr8MwhYrnX1z3vKzpW9rh4vF8rA=');
    config()->set('app.env', 'production');
    config()->set('app.debug', false);
    config()->set('session.secure', true);
    config()->set('session.http_only', true);
    config()->set('session.same_site', 'lax');
    config()->set('session.encrypt', true);
    config()->set('session.lifetime', 120);
    $checks = config('larascan.checks', []);
    $checks['php.display-errors'] = ['enabled' => false];
    $checks['injection.host-header'] = ['enabled' => false];
    config()->set('larascan.checks', $checks);

    $this->artisan('larascan --category=config')
        ->expectsOutputToContain('larascan')
        ->assertExitCode(0);
});

it('exits 1 when a check fails at or above the --fail-on threshold', function () {
    config()->set('app.env', 'production');
    config()->set('app.debug', true);

    $this->artisan('larascan --fail-on=critical')
        ->expectsOutputToContain('config.app-debug')
        ->assertExitCode(1);
});

it('honors --only-failed flag', function () {
    // Clean prod setup so no shipped check fires above the default fail_on=high.
    config()->set('app.key', 'base64:fJjK9p8wQYJxhmKQYr8MwhYrnX1z3vKzpW9rh4vF8rA=');
    config()->set('app.env', 'production');
    config()->set('app.debug', false);
    config()->set('session.secure', true);
    config()->set('session.http_only', true);
    config()->set('session.same_site', 'lax');
    config()->set('session.encrypt', true);
    config()->set('session.lifetime', 120);
    $checks = config('larascan.checks', []);
    $checks['headers.hsts'] = ['enabled' => false];
    $checks['headers.x-content-type-options'] = ['enabled' => false];
    $checks['headers.x-frame-options'] = ['enabled' => false];
    $checks['php.display-errors'] = ['enabled' => false];
    $checks['csrf.middleware-disabled'] = ['enabled' => false];
    $checks['injection.host-header'] = ['enabled' => false];
    config()->set('larascan.checks', $checks);

    $this->artisan('larascan --only-failed --format=human')
        ->assertExitCode(0);
});

it('renders JSON output when --format=json', function () {
    // Clean prod setup so no shipped check fires above the default fail_on=high.
    config()->set('app.key', 'base64:fJjK9p8wQYJxhmKQYr8MwhYrnX1z3vKzpW9rh4vF8rA=');
    config()->set('app.env', 'production');
    config()->set('app.debug', false);
    config()->set('session.secure', true);
    config()->set('session.http_only', true);
    config()->set('session.same_site', 'lax');
    config()->set('session.encrypt', true);
    config()->set('session.lifetime', 120);
    $checks = config('larascan.checks', []);
    $checks['headers.hsts'] = ['enabled' => false];
    $checks['headers.x-content-type-options'] = ['enabled' => false];
    $checks['headers.x-frame-options'] = ['enabled' => false];
    $checks['php.display-errors'] = ['enabled' => false];
    $checks['csrf.middleware-disabled'] = ['enabled' => false];
    $checks['injection.host-header'] = ['enabled' => false];
    config()->set('larascan.checks', $checks);

    $this->artisan('larascan --format=json')
        ->assertExitCode(0);
});

it('renders decodable SARIF 2.1.0 when --format=sarif', function () {
    config()->set('app.env', 'production');
    config()->set('app.debug', true);

    $this->withoutMockingConsoleOutput();
    $exitCode = $this->artisan('larascan --format=sarif --fail-on=critical --check=config.app-debug');
    $output = Artisan::output();

    $decoded = json_decode($output, true);

    expect($exitCode)->toBe(1)
        ->and($decoded)->toBeArray()
        ->and($decoded['version'])->toBe('2.1.0')
        ->and($decoded['$schema'])->toBe('https://json.schemastore.org/sarif-2.1.0.json')
        ->and($decoded['runs'][0]['tool']['driver']['name'])->toBe('Larascan')
        ->and($decoded['runs'][0]['results'])->not->toBeEmpty();
});

it('writes SARIF to a file and prints the human report with --output', function () {
    config()->set('app.env', 'production');
    config()->set('app.debug', true);

    $path = sys_get_temp_dir().'/larascan-sarif-'.uniqid().'.sarif';

    try {
        $this->artisan('larascan', ['--format' => 'sarif', '--output' => $path, '--fail-on' => 'critical', '--check' => ['config.app-debug']])
            ->expectsOutputToContain('Report Card')
            ->expectsOutputToContain("Report written to {$path}")
            ->assertExitCode(1);

        $decoded = json_decode((string) file_get_contents($path), true);
        expect($decoded['version'])->toBe('2.1.0')
            ->and($decoded['runs'][0]['results'])->not->toBeEmpty();
    } finally {
        if (is_file($path)) {
            unlink($path);
        }
    }
});

it('exits 2 when --output cannot be written', function () {
    config()->set('app.env', 'production');
    config()->set('app.debug', true);

    // An existing directory is not writable as a file.
    $path = sys_get_temp_dir();

    $this->artisan('larascan', ['--format' => 'sarif', '--output' => $path, '--fail-on' => 'critical', '--check' => ['config.app-debug']])
        ->expectsOutputToContain("Could not write report to {$path}")
        ->assertExitCode(2);
});

it('exits 2 on invalid --format value', function () {
    $this->artisan('larascan --format=bogus')
        ->expectsOutputToContain('Invalid --format value: bogus')
        ->assertExitCode(2);
});

it('suppresses baselined findings and exits 0', function () {
    config()->set('app.key', 'base64:fJjK9p8wQYJxhmKQYr8MwhYrnX1z3vKzpW9rh4vF8rA=');
    config()->set('app.env', 'production');
    config()->set('app.debug', true);

    $path = sys_get_temp_dir().'/larascan-scan-baseline-'.uniqid().'.json';

    try {
        $this->artisan('larascan:baseline', ['--baseline' => $path])->assertExitCode(0);

        $this->artisan('larascan', ['--baseline' => $path])
            ->expectsOutputToContain('baselined')
            ->assertExitCode(0);
    } finally {
        if (is_file($path)) {
            unlink($path);
        }
    }
});

it('still fails on new findings not in the baseline', function () {
    config()->set('app.key', 'base64:fJjK9p8wQYJxhmKQYr8MwhYrnX1z3vKzpW9rh4vF8rA=');
    config()->set('app.env', 'production');
    config()->set('app.debug', true);

    $path = sys_get_temp_dir().'/larascan-scan-baseline-'.uniqid().'.json';

    try {
        $this->artisan('larascan:baseline', ['--baseline' => $path])->assertExitCode(0);

        // Introduce a NEW critical finding after the baseline was written.
        config()->set('app.key', '');

        $this->artisan('larascan', ['--baseline' => $path])
            ->expectsOutputToContain('config.app-key')
            ->assertExitCode(1);
    } finally {
        if (is_file($path)) {
            unlink($path);
        }
    }
});

it('ignores the baseline with --no-baseline', function () {
    config()->set('app.key', 'base64:fJjK9p8wQYJxhmKQYr8MwhYrnX1z3vKzpW9rh4vF8rA=');
    config()->set('app.env', 'production');
    config()->set('app.debug', true);

    $path = sys_get_temp_dir().'/larascan-scan-baseline-'.uniqid().'.json';

    try {
        $this->artisan('larascan:baseline', ['--baseline' => $path])->assertExitCode(0);

        $this->artisan('larascan', ['--baseline' => $path, '--no-baseline' => true])
            ->assertExitCode(1);
    } finally {
        if (is_file($path)) {
            unlink($path);
        }
    }
});

it('exits 2 when an explicit baseline file does not exist', function () {
    $this->artisan('larascan', ['--baseline' => '/nonexistent/larascan-baseline.json'])
        ->expectsOutputToContain('Baseline file not found')
        ->assertExitCode(2);
});

it('shows a stale hint when baseline entries no longer match', function () {
    config()->set('app.key', 'base64:fJjK9p8wQYJxhmKQYr8MwhYrnX1z3vKzpW9rh4vF8rA=');
    config()->set('app.env', 'production');
    config()->set('app.debug', true);

    $path = sys_get_temp_dir().'/larascan-scan-baseline-'.uniqid().'.json';

    try {
        $this->artisan('larascan:baseline', ['--baseline' => $path])->assertExitCode(0);

        // Add an entry that matches nothing in the current scan.
        $data = json_decode((string) file_get_contents($path), true);
        $data['findings'][] = [
            'check' => 'config.app-debug',
            'file' => null,
            'message' => 'this finding no longer exists',
            'severity' => 'high',
            'count' => 1,
        ];
        file_put_contents($path, json_encode($data));

        $this->artisan('larascan', ['--baseline' => $path])
            ->expectsOutputToContain('stale baseline entry')
            ->assertExitCode(0);
    } finally {
        if (is_file($path)) {
            unlink($path);
        }
    }
});

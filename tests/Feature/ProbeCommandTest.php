<?php

declare(strict_types=1);

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;

$AGENT_VARS = [
    'AI_AGENT', 'CLAUDECODE', 'CLAUDE_CODE', 'CLAUDE_CODE_IS_COWORK', 'CURSOR_AGENT',
    'GEMINI_CLI', 'CODEX_SANDBOX', 'CODEX_CI', 'CODEX_THREAD_ID', 'AUGMENT_AGENT',
    'OPENCODE_CLIENT', 'OPENCODE', 'AMP_CURRENT_THREAD_ID', 'REPL_ID', 'COPILOT_MODEL',
    'COPILOT_ALLOW_ALL', 'COPILOT_GITHUB_TOKEN', 'COPILOT_CLI', 'ANTIGRAVITY_AGENT',
    'PI_CODING_AGENT', 'KIRO_AGENT_PATH', 'LARASCAN_AGENT_MODE',
];

beforeEach(function () use ($AGENT_VARS) {
    $this->originalAgentEnv = [];
    foreach ($AGENT_VARS as $var) {
        $this->originalAgentEnv[$var] = getenv($var);
        putenv($var);
    }
    Http::preventStrayRequests();
});

afterEach(function () use ($AGENT_VARS) {
    foreach ($AGENT_VARS as $var) {
        $original = $this->originalAgentEnv[$var] ?? false;
        $original === false ? putenv($var) : putenv("{$var}={$original}");
    }
});

/**
 * A fully-secured response so all probes pass.
 */
function secureResponses(): array
{
    return [
        'https://example.com' => Http::response('', 200, [
            'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => 'DENY',
            'Referrer-Policy' => 'strict-origin-when-cross-origin',
            'Content-Security-Policy' => "default-src 'self'; script-src 'self'",
            'Set-Cookie' => 'laravel_session=abc; path=/; Secure; HttpOnly; SameSite=Lax',
        ]),
        'http://example.com' => Http::response('', 301, ['Location' => 'https://example.com/']),
    ];
}

it('exits 0 when every probe passes', function () {
    Http::fake(secureResponses());

    $this->artisan('larascan:probe', ['--url' => 'https://example.com'])
        ->expectsOutputToContain('Probing https://example.com — one GET request will be sent.')
        ->assertExitCode(0);
});

it('exits 1 with HSTS missing and --fail-on=high', function () {
    $responses = secureResponses();
    $responses['https://example.com'] = Http::response('', 200, [
        'X-Content-Type-Options' => 'nosniff',
        'X-Frame-Options' => 'DENY',
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
        'Content-Security-Policy' => "default-src 'self'; script-src 'self'",
        'Set-Cookie' => 'laravel_session=abc; path=/; Secure; HttpOnly; SameSite=Lax',
    ]);
    Http::fake($responses);

    $this->artisan('larascan:probe', ['--url' => 'https://example.com', '--fail-on' => 'high'])
        ->assertExitCode(1);
});

it('exits 2 on a connection failure', function () {
    Http::fake(fn () => throw new ConnectionException('connection refused'));

    $this->artisan('larascan:probe', ['--url' => 'https://example.com'])
        ->assertExitCode(2);
});

it('exits 0 on a connection failure when --ignore-errors is set', function () {
    Http::fake(fn () => throw new ConnectionException('connection refused'));

    $this->artisan('larascan:probe', ['--url' => 'https://example.com', '--ignore-errors' => true])
        ->assertExitCode(0);
});

it('exits 2 on a missing URL', function () {
    config()->set('larascan.probe.url', null);
    config()->set('app.url', null);

    $this->artisan('larascan:probe')
        ->assertExitCode(2);
});

it('exits 2 on an invalid URL', function () {
    $this->artisan('larascan:probe', ['--url' => 'not-a-url'])
        ->assertExitCode(2);
});

it('emits JSON output with --format=json', function () {
    Http::fake(secureResponses());

    $this->artisan('larascan:probe', ['--url' => 'https://example.com', '--format' => 'json'])
        ->expectsOutputToContain('"version"')
        ->assertExitCode(0);
});

it('filters probes by id pattern', function () {
    Http::fake(secureResponses());

    $this->artisan('larascan:probe', ['--url' => 'https://example.com', '--probe' => ['probe.hsts'], '--format' => 'json'])
        ->doesntExpectOutputToContain('probe.csp')
        ->expectsOutputToContain('probe.hsts')
        ->assertExitCode(0);
});

it('keeps a config-disabled probe disabled even when matched by --probe', function () {
    config()->set('larascan.probe.probes', ['probe.hsts' => ['enabled' => false]]);
    Http::fake(secureResponses());

    $this->artisan('larascan:probe', ['--url' => 'https://example.com', '--probe' => ['probe.hsts'], '--format' => 'json'])
        ->doesntExpectOutputToContain('probe.hsts')
        ->assertExitCode(0);
});

it('exits 2 on an invalid --fail-on value', function () {
    $this->artisan('larascan:probe', ['--url' => 'https://example.com', '--fail-on' => 'nonsense'])
        ->expectsOutputToContain('Invalid --fail-on value: nonsense')
        ->assertExitCode(2);
});

it('exits 2 on an invalid --format value', function () {
    $this->artisan('larascan:probe', ['--url' => 'https://example.com', '--format' => 'xml'])
        ->expectsOutputToContain('Invalid --format value: xml')
        ->assertExitCode(2);
});

it('falls back to larascan.fail_on config when no flag is given', function () {
    // An info threshold means even a Low finding (short HSTS) fails the run.
    config()->set('larascan.fail_on', 'info');
    $responses = secureResponses();
    $responses['https://example.com'] = Http::response('', 200, [
        'Strict-Transport-Security' => 'max-age=3600',
        'X-Content-Type-Options' => 'nosniff',
        'X-Frame-Options' => 'DENY',
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
        'Content-Security-Policy' => "default-src 'self'; script-src 'self'",
        'Set-Cookie' => 'laravel_session=abc; path=/; Secure; HttpOnly; SameSite=Lax',
    ]);
    Http::fake($responses);

    $this->artisan('larascan:probe', ['--url' => 'https://example.com'])
        ->assertExitCode(1);
});

it('honors a numeric --timeout option', function () {
    Http::fake(secureResponses());

    $this->artisan('larascan:probe', ['--url' => 'https://example.com', '--timeout' => '10'])
        ->assertExitCode(0);
});

it('auto-selects json output when running under an agent', function () {
    putenv('LARASCAN_AGENT_MODE=1');
    Http::fake(secureResponses());

    $this->artisan('larascan:probe', ['--url' => 'https://example.com'])
        ->expectsOutputToContain('"version"')
        ->assertExitCode(0);
});

it('hides passed probes with --only-failed', function () {
    $responses = secureResponses();
    // Drop HSTS so probe.hsts fails while the rest pass.
    $responses['https://example.com'] = Http::response('', 200, [
        'X-Content-Type-Options' => 'nosniff',
        'X-Frame-Options' => 'DENY',
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
        'Content-Security-Policy' => "default-src 'self'; script-src 'self'",
        'Set-Cookie' => 'laravel_session=abc; path=/; Secure; HttpOnly; SameSite=Lax',
    ]);
    Http::fake($responses);

    $this->artisan('larascan:probe', ['--url' => 'https://example.com', '--only-failed' => true, '--fail-on' => 'critical'])
        ->expectsOutputToContain('probe.hsts')
        ->doesntExpectOutputToContain('probe.csp')
        ->assertExitCode(0);
});

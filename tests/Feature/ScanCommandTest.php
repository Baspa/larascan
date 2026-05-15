<?php

declare(strict_types=1);

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
        ->expectsOutputToContain('larascan — security scan')
        ->expectsOutputToContain('Report')
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
        ->expectsOutputToContain('larascan — security scan')
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
        ->expectsOutputToContain('larascan — security scan')
        ->assertExitCode(0);
});

it('exits 1 when a check fails at or above the --fail-on threshold', function () {
    config()->set('app.env', 'production');
    config()->set('app.debug', true);

    $this->artisan('larascan --fail-on=critical')
        ->expectsOutputToContain('config.app-debug')
        ->assertExitCode(1);
});

it('renders plain output when --format=plain', function () {
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

    $this->artisan('larascan --format=plain')
        ->expectsOutputToContain('larascan — security scan')
        ->expectsOutputToContain('Report')
        ->assertExitCode(0);
});

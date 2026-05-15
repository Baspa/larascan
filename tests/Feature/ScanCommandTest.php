<?php

declare(strict_types=1);

it('runs the larascan command and shows the report', function () {
    config()->set('app.key', 'base64:fJjK9p8wQYJxhmKQYr8MwhYrnX1z3vKzpW9rh4vF8rA=');

    $this->artisan('larascan')
        ->expectsOutputToContain('larascan — security scan')
        ->expectsOutputToContain('Report')
        ->assertExitCode(0);
});

it('honors --fail-on for exit code', function () {
    // With AppKeyCheck registered, testbench's empty app.key would yield a
    // Critical finding. Set a key so the scan runs cleanly.
    config()->set('app.key', 'base64:fJjK9p8wQYJxhmKQYr8MwhYrnX1z3vKzpW9rh4vF8rA=');

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
    config()->set('app.key', 'base64:fJjK9p8wQYJxhmKQYr8MwhYrnX1z3vKzpW9rh4vF8rA=');

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

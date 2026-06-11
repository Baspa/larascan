<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Ecosystem\DebugbarEnabledCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new DebugbarEnabledCheck($this->app);

    expect($check->id())->toBe('ecosystem.debugbar-enabled')
        ->and($check->category())->toBe(Category::Ecosystem)
        ->and($check->severity())->toBe(Severity::High)
        ->and($check->docsUrl())->toBe('https://github.com/baspa/larascan/blob/main/docs/checks/ecosystem/debugbar-enabled.md');
});

it('is not applicable when Debugbar is not installed', function () {
    if (class_exists('Barryvdh\\Debugbar\\LaravelDebugbar')) {
        $this->markTestSkipped('Debugbar is installed; cannot test the not-installed branch.');
    }

    $check = new DebugbarEnabledCheck($this->app);
    expect($check->isApplicable())->toBeFalse();
});

it('passes outside production even when debugbar is enabled', function () {
    config()->set('app.env', 'local');
    config()->set('debugbar.enabled', true);

    $findings = iterator_to_array((new DebugbarEnabledCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('passes in production when debugbar.enabled is false', function () {
    config()->set('app.env', 'production');
    config()->set('debugbar.enabled', false);
    config()->set('app.debug', true);

    $findings = iterator_to_array((new DebugbarEnabledCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails Critical when debugbar.enabled is explicitly true in production', function () {
    config()->set('app.env', 'production');
    config()->set('debugbar.enabled', true);

    $findings = iterator_to_array((new DebugbarEnabledCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('ecosystem.debugbar-enabled')
        ->and($findings[0]->message)->toContain('repo.debug-toolbars');
});

it('fails High when debugbar.enabled is null and app.debug is true in production', function () {
    config()->set('app.env', 'production');
    config()->set('debugbar.enabled', null);
    config()->set('app.debug', true);

    $findings = iterator_to_array((new DebugbarEnabledCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->message)->toContain('follows app.debug');
});

it("fails Critical when debugbar.enabled is the env string '1' in production", function () {
    config()->set('app.env', 'production');
    config()->set('debugbar.enabled', '1');

    $findings = iterator_to_array((new DebugbarEnabledCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('ecosystem.debugbar-enabled');
});

it("fails High when debugbar.enabled is null and app.debug is the env string '1' in production", function () {
    config()->set('app.env', 'production');
    config()->set('debugbar.enabled', null);
    config()->set('app.debug', '1');

    $findings = iterator_to_array((new DebugbarEnabledCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->message)->toContain('follows app.debug');
});

it("passes in production when debugbar.enabled is the env string 'false'", function () {
    config()->set('app.env', 'production');
    config()->set('debugbar.enabled', 'false');
    config()->set('app.debug', true);

    $findings = iterator_to_array((new DebugbarEnabledCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('passes when debugbar.enabled is null and app.debug is false in production', function () {
    config()->set('app.env', 'production');
    config()->set('debugbar.enabled', null);
    config()->set('app.debug', false);

    $findings = iterator_to_array((new DebugbarEnabledCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

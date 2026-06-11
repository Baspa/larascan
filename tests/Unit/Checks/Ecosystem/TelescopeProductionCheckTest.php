<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Ecosystem\TelescopeProductionCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Illuminate\Support\Facades\Gate;

it('exposes correct metadata', function () {
    $check = new TelescopeProductionCheck($this->app);

    expect($check->id())->toBe('ecosystem.telescope-production')
        ->and($check->category())->toBe(Category::Ecosystem)
        ->and($check->severity())->toBe(Severity::High)
        ->and($check->docsUrl())->toBe('https://github.com/baspa/larascan/blob/main/docs/checks/ecosystem/telescope-production.md');
});

it('is not applicable when Telescope is not installed', function () {
    if (class_exists('Laravel\\Telescope\\Telescope')) {
        $this->markTestSkipped('Telescope is installed; cannot test the not-installed branch.');
    }

    $check = new TelescopeProductionCheck($this->app);
    expect($check->isApplicable())->toBeFalse();
});

it('passes outside production even when telescope is enabled', function () {
    config()->set('app.env', 'local');
    config()->set('telescope.enabled', true);

    $findings = iterator_to_array((new TelescopeProductionCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('passes in production when telescope is disabled', function () {
    config()->set('app.env', 'production');
    config()->set('telescope.enabled', false);

    $findings = iterator_to_array((new TelescopeProductionCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails Critical when enabled in production without a viewTelescope gate', function () {
    config()->set('app.env', 'production');
    config()->set('telescope.enabled', true);

    $findings = iterator_to_array((new TelescopeProductionCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('ecosystem.telescope-production')
        ->and($findings[0]->message)->toContain('viewTelescope');
});

it("passes in production when telescope.enabled is the env string 'false'", function () {
    config()->set('app.env', 'production');
    config()->set('telescope.enabled', 'false');

    $findings = iterator_to_array((new TelescopeProductionCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it("fails Critical when telescope.enabled is the env string '1' in production", function () {
    config()->set('app.env', 'production');
    config()->set('telescope.enabled', '1');

    $findings = iterator_to_array((new TelescopeProductionCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical);
});

it('treats a missing telescope.enabled key as enabled (defaults to true)', function () {
    config()->set('app.env', 'production');

    $findings = iterator_to_array((new TelescopeProductionCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical);
});

it('fails Medium when enabled in production with a viewTelescope gate', function () {
    config()->set('app.env', 'production');
    config()->set('telescope.enabled', true);
    Gate::define('viewTelescope', fn () => false);

    $findings = iterator_to_array((new TelescopeProductionCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->message)->toContain('verify the viewTelescope gate');
});

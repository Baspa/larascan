<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Ecosystem\PulseGateCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;
use Illuminate\Support\Facades\Gate;

function pulseCheck(string $fixtureSet, $app): PulseGateCheck
{
    return new PulseGateCheck(
        basePath: __DIR__.'/../../../Fixtures/Providers/'.$fixtureSet,
        parser: new FileParser,
        app: $app,
    );
}

it('exposes correct metadata', function () {
    $check = pulseCheck('legit-gate', $this->app);

    expect($check->id())->toBe('ecosystem.pulse-gate')
        ->and($check->category())->toBe(Category::Ecosystem)
        ->and($check->severity())->toBe(Severity::High)
        ->and($check->docsUrl())->toBe('https://github.com/baspa/larascan/blob/main/docs/checks/ecosystem/pulse-gate.md');
});

it('is not applicable when Pulse is not installed', function () {
    if (class_exists('Laravel\\Pulse\\Pulse')) {
        $this->markTestSkipped('Pulse is installed; cannot test the not-installed branch.');
    }

    expect(pulseCheck('legit-gate', $this->app)->isApplicable())->toBeFalse();
});

it('fails Critical when the viewPulse gate is trivially true in PulseServiceProvider', function () {
    $findings = iterator_to_array(pulseCheck('trivial-gate', $this->app)->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('ecosystem.pulse-gate')
        ->and($findings[0]->message)->toContain('viewPulse')
        ->and($findings[0]->file)->toBe('app/Providers/PulseServiceProvider.php')
        ->and($findings[0]->line)->toBe(12);
});

it('also scans AppServiceProvider for a trivially-true viewPulse gate', function () {
    $findings = iterator_to_array(pulseCheck('trivial-gate-app', $this->app)->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->file)->toBe('app/Providers/AppServiceProvider.php');
});

it('passes outside production when the gate has real logic', function () {
    config()->set('app.env', 'testing');

    $findings = iterator_to_array(pulseCheck('legit-gate', $this->app)->run());
    expect($findings)->toBeEmpty();
});

it('yields Info in production when no viewPulse gate is defined at runtime', function () {
    config()->set('app.env', 'production');

    $findings = iterator_to_array(pulseCheck('legit-gate', $this->app)->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Info)
        ->and($findings[0]->message)->toContain('locked to the local environment');
});

it('passes in production when the viewPulse gate is defined at runtime', function () {
    config()->set('app.env', 'production');
    Gate::define('viewPulse', fn ($user) => true);

    $findings = iterator_to_array(pulseCheck('legit-gate', $this->app)->run());
    expect($findings)->toBeEmpty();
});

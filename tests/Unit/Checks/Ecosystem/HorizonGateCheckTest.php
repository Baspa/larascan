<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Ecosystem\HorizonGateCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;
use Illuminate\Support\Facades\Gate;

function horizonCheck(string $fixtureSet, $app): HorizonGateCheck
{
    return new HorizonGateCheck(
        basePath: __DIR__.'/../../../Fixtures/Providers/'.$fixtureSet,
        parser: new FileParser,
        app: $app,
    );
}

it('exposes correct metadata', function () {
    $check = horizonCheck('legit-gate', $this->app);

    expect($check->id())->toBe('ecosystem.horizon-gate')
        ->and($check->category())->toBe(Category::Ecosystem)
        ->and($check->severity())->toBe(Severity::High)
        ->and($check->docsUrl())->toBe('https://github.com/baspa/larascan/blob/main/docs/checks/ecosystem/horizon-gate.md');
});

it('is not applicable when Horizon is not installed', function () {
    if (class_exists('Laravel\\Horizon\\Horizon')) {
        $this->markTestSkipped('Horizon is installed; cannot test the not-installed branch.');
    }

    expect(horizonCheck('legit-gate', $this->app)->isApplicable())->toBeFalse();
});

it('fails Critical with file and line when the viewHorizon gate is trivially true', function () {
    $findings = iterator_to_array(horizonCheck('trivial-gate', $this->app)->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('ecosystem.horizon-gate')
        ->and($findings[0]->message)->toContain('viewHorizon')
        ->and($findings[0]->file)->toBe('app/Providers/HorizonServiceProvider.php')
        ->and($findings[0]->line)->toBe(12);
});

it('finds a trivially-true viewHorizon gate in a differently-named provider', function () {
    $findings = iterator_to_array(horizonCheck('trivial-gate-auth', $this->app)->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('ecosystem.horizon-gate')
        ->and($findings[0]->file)->toBe('app/Providers/AuthServiceProvider.php');
});

it('passes outside production when the gate has real logic', function () {
    config()->set('app.env', 'testing');

    $findings = iterator_to_array(horizonCheck('legit-gate', $this->app)->run());
    expect($findings)->toBeEmpty();
});

it('yields Info in production when no viewHorizon gate is defined at runtime', function () {
    config()->set('app.env', 'production');

    $findings = iterator_to_array(horizonCheck('legit-gate', $this->app)->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Info)
        ->and($findings[0]->message)->toContain('locked to the local environment');
});

it('passes in production when the viewHorizon gate is defined at runtime', function () {
    config()->set('app.env', 'production');
    Gate::define('viewHorizon', fn ($user) => true);

    $findings = iterator_to_array(horizonCheck('legit-gate', $this->app)->run());
    expect($findings)->toBeEmpty();
});

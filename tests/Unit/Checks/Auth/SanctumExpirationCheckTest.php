<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Auth\SanctumExpirationCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new SanctumExpirationCheck($this->app);

    expect($check->id())->toBe('auth.sanctum-expiration')
        ->and($check->category())->toBe(Category::Auth)
        ->and($check->severity())->toBe(Severity::Medium)
        ->and($check->docsUrl())->toBe('https://github.com/baspa/larascan/blob/main/docs/checks/auth/sanctum-expiration.md');
});

it('is not applicable when Sanctum is not installed', function () {
    if (class_exists('Laravel\\Sanctum\\Sanctum')) {
        $this->markTestSkipped('Sanctum is installed; cannot test the not-installed branch.');
    }

    $check = new SanctumExpirationCheck($this->app);
    expect($check->isApplicable())->toBeFalse();
});

it('passes when sanctum.expiration is an integer', function () {
    if (! class_exists('Laravel\\Sanctum\\Sanctum')) {
        $this->markTestSkipped('Sanctum is not installed.');
    }

    config()->set('sanctum.expiration', 1440);

    $findings = iterator_to_array((new SanctumExpirationCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails when sanctum.expiration is null', function () {
    if (! class_exists('Laravel\\Sanctum\\Sanctum')) {
        $this->markTestSkipped('Sanctum is not installed.');
    }

    config()->set('sanctum.expiration', null);

    $findings = iterator_to_array((new SanctumExpirationCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->checkId)->toBe('auth.sanctum-expiration')
        ->and($findings[0]->message)->toContain('never expire');
});

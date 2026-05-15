<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Config\AppKeyCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new AppKeyCheck($this->app);

    expect($check->id())->toBe('config.app-key')
        ->and($check->category())->toBe(Category::Config)
        ->and($check->severity())->toBe(Severity::Critical);
});

it('is applicable in any environment', function () {
    $check = new AppKeyCheck($this->app);
    config()->set('app.env', 'local');
    expect($check->isApplicable())->toBeTrue();
    config()->set('app.env', 'production');
    expect($check->isApplicable())->toBeTrue();
});

it('passes when app.key is a non-empty string', function () {
    config()->set('app.key', 'base64:fJjK9p8wQYJxhmKQYr8MwhYrnX1z3vKzpW9rh4vF8rA=');
    $findings = iterator_to_array((new AppKeyCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails when app.key is empty string', function () {
    config()->set('app.key', '');
    $findings = iterator_to_array((new AppKeyCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->message)->toContain('APP_KEY');
});

it('fails when app.key is null', function () {
    config()->set('app.key', null);
    $findings = iterator_to_array((new AppKeyCheck($this->app))->run());
    expect($findings)->toHaveCount(1);
});

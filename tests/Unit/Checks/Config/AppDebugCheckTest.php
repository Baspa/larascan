<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Config\AppDebugCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new AppDebugCheck($this->app);

    expect($check->id())->toBe('config.app-debug')
        ->and($check->category())->toBe(Category::Config)
        ->and($check->severity())->toBe(Severity::Critical);
});

it('is only applicable in production', function () {
    $check = new AppDebugCheck($this->app);

    config()->set('app.env', 'local');
    expect($check->isApplicable())->toBeFalse();

    config()->set('app.env', 'production');
    expect($check->isApplicable())->toBeTrue();
});

it('passes when APP_DEBUG is false in production', function () {
    config()->set('app.env', 'production');
    config()->set('app.debug', false);

    $findings = iterator_to_array((new AppDebugCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails when APP_DEBUG is true in production', function () {
    config()->set('app.env', 'production');
    config()->set('app.debug', true);

    $findings = iterator_to_array((new AppDebugCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('config.app-debug');
});

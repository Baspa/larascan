<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Config\AppEnvCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new AppEnvCheck($this->app);

    expect($check->id())->toBe('config.app-env')
        ->and($check->category())->toBe(Category::Config)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when APP_ENV is production', function () {
    config()->set('app.env', 'production');
    $findings = iterator_to_array((new AppEnvCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('passes when APP_ENV is staging', function () {
    config()->set('app.env', 'staging');
    $findings = iterator_to_array((new AppEnvCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails when APP_ENV is local', function () {
    config()->set('app.env', 'local');
    $findings = iterator_to_array((new AppEnvCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Info);
});

it('fails when APP_ENV is testing', function () {
    config()->set('app.env', 'testing');
    $findings = iterator_to_array((new AppEnvCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Info);
});

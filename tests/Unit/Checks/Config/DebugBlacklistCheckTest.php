<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Config\DebugBlacklistCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new DebugBlacklistCheck($this->app);

    expect($check->id())->toBe('config.debug-blacklist')
        ->and($check->category())->toBe(Category::Config)
        ->and($check->severity())->toBe(Severity::Medium);
});

it('is only applicable when app.debug is true', function () {
    $check = new DebugBlacklistCheck($this->app);

    config()->set('app.debug', false);
    expect($check->isApplicable())->toBeFalse();

    config()->set('app.debug', true);
    expect($check->isApplicable())->toBeTrue();
});

it('passes when debug_blacklist contains non-empty entries', function () {
    config()->set('app.debug', true);
    config()->set('app.debug_blacklist', ['_ENV' => ['APP_KEY', 'DB_PASSWORD']]);

    expect(iterator_to_array((new DebugBlacklistCheck($this->app))->run()))->toBeEmpty();
});

it('fails when debug_blacklist is empty', function () {
    config()->set('app.debug', true);
    config()->set('app.debug_blacklist', []);

    $findings = iterator_to_array((new DebugBlacklistCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->message)->toContain('debug');
});

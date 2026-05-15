<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Config\LogLevelCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new LogLevelCheck($this->app);

    expect($check->id())->toBe('config.log-level')
        ->and($check->category())->toBe(Category::Config)
        ->and($check->severity())->toBe(Severity::Low);
});

it('is only applicable in production', function () {
    $check = new LogLevelCheck($this->app);
    config()->set('app.env', 'local');
    expect($check->isApplicable())->toBeFalse();
    config()->set('app.env', 'production');
    expect($check->isApplicable())->toBeTrue();
});

it('passes when default channel is at info or higher', function () {
    config()->set('app.env', 'production');
    config()->set('logging.default', 'single');
    config()->set('logging.channels.single.level', 'info');

    $findings = iterator_to_array((new LogLevelCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails when default channel is at debug', function () {
    config()->set('app.env', 'production');
    config()->set('logging.default', 'single');
    config()->set('logging.channels.single.level', 'debug');

    $findings = iterator_to_array((new LogLevelCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Low)
        ->and($findings[0]->message)->toContain('debug');
});

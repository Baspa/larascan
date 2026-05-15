<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Injection\HostHeaderCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new HostHeaderCheck($this->app);

    expect($check->id())->toBe('injection.host-header')
        ->and($check->category())->toBe(Category::Injection)
        ->and($check->severity())->toBe(Severity::Medium);
});

it('passes when app.url is a real URL', function () {
    config()->set('app.env', 'production');
    config()->set('app.url', 'https://example.com');

    $findings = iterator_to_array((new HostHeaderCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails when app.url is null', function () {
    config()->set('app.env', 'production');
    config()->set('app.url', null);

    $findings = iterator_to_array((new HostHeaderCheck($this->app))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->checkId)->toBe('injection.host-header')
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->message)->toContain('host header injection');
});

it('fails when app.url contains localhost and downgrades in dev', function () {
    config()->set('app.env', 'local');
    config()->set('app.url', 'http://localhost');

    $findings = iterator_to_array((new HostHeaderCheck($this->app))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->checkId)->toBe('injection.host-header')
        ->and($findings[0]->severity)->toBe(Severity::Info);
});

<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Config\TrustedProxiesCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new TrustedProxiesCheck($this->app);

    expect($check->id())->toBe('config.trusted-proxies')
        ->and($check->category())->toBe(Category::Config)
        ->and($check->severity())->toBe(Severity::Medium);
});

it('passes when trustedproxy.proxies is a specific list', function () {
    config()->set('trustedproxy.proxies', ['10.0.0.1', '192.168.1.0/24']);

    expect(iterator_to_array((new TrustedProxiesCheck($this->app))->run()))->toBeEmpty();
});

it('fails when trustedproxy.proxies is wildcard string', function () {
    config()->set('trustedproxy.proxies', '*');

    $findings = iterator_to_array((new TrustedProxiesCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->message)->toContain('wildcard');
});

it('fails when trustedproxy.proxies contains wildcard in array', function () {
    config()->set('trustedproxy.proxies', ['*']);

    $findings = iterator_to_array((new TrustedProxiesCheck($this->app))->run());
    expect($findings)->toHaveCount(1);
});

it('passes when trustedproxy config is absent', function () {
    config()->set('trustedproxy.proxies', null);

    expect(iterator_to_array((new TrustedProxiesCheck($this->app))->run()))->toBeEmpty();
});

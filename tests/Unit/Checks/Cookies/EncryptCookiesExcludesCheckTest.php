<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Cookies\EncryptCookiesExcludesCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Illuminate\Cookie\Middleware\EncryptCookies;

beforeEach(function () {
    config()->set('app.key', 'base64:fJjK9p8wQYJxhmKQYr8MwhYrnX1z3vKzpW9rh4vF8rA=');
});

it('exposes correct metadata', function () {
    $check = new EncryptCookiesExcludesCheck($this->app);

    expect($check->id())->toBe('cookies.encrypt-excludes')
        ->and($check->category())->toBe(Category::Cookies)
        ->and($check->severity())->toBe(Severity::Medium);
});

it('passes when except list is empty', function () {
    $mw = $this->app->make(EncryptCookies::class);
    $r = new ReflectionClass($mw);
    $r->getProperty('except')->setValue($mw, []);
    $this->app->instance(EncryptCookies::class, $mw);

    expect(iterator_to_array((new EncryptCookiesExcludesCheck($this->app))->run()))->toBeEmpty();
});

it('passes when except list contains only innocuous cookies', function () {
    $mw = $this->app->make(EncryptCookies::class);
    $r = new ReflectionClass($mw);
    $r->getProperty('except')->setValue($mw, ['ui_theme', 'preferred_locale']);
    $this->app->instance(EncryptCookies::class, $mw);

    expect(iterator_to_array((new EncryptCookiesExcludesCheck($this->app))->run()))->toBeEmpty();
});

it('fails for each sensitive cookie in the except list', function () {
    $mw = $this->app->make(EncryptCookies::class);
    $r = new ReflectionClass($mw);
    $r->getProperty('except')->setValue($mw, ['ui_theme', 'remember_web_xxx', 'XSRF-TOKEN', 'auth_session']);
    $this->app->instance(EncryptCookies::class, $mw);

    $findings = iterator_to_array((new EncryptCookiesExcludesCheck($this->app))->run());

    expect($findings)->toHaveCount(3);
    foreach ($findings as $f) {
        expect($f->severity)->toBe(Severity::Medium);
    }
});

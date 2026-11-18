<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Cookies\EncryptCookiesExcludesCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Baspa\Larascan\Tests\Fixtures\Middleware\AppEncryptCookies;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Foundation\Configuration\Middleware;

beforeEach(function () {
    config()->set('app.key', 'base64:fJjK9p8wQYJxhmKQYr8MwhYrnX1z3vKzpW9rh4vF8rA=');
    EncryptCookies::flushState();
});

afterEach(function () {
    EncryptCookies::flushState();
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

it('fails for a sensitive cookie excluded through bootstrap/app.php', function () {
    (new Middleware)->encryptCookies(except: ['ui_theme', 'remember_web_xxx']);

    $findings = iterator_to_array((new EncryptCookiesExcludesCheck($this->app))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->message)->toContain("'remember_web_xxx'");
});

it('fails when an app middleware extending EncryptCookies excludes a sensitive cookie', function () {
    $kernel = $this->app->make(Kernel::class);
    (new ReflectionClass($kernel))->getProperty('middlewareGroups')->setValue($kernel, [
        'web' => [AppEncryptCookies::class],
    ]);

    $findings = iterator_to_array((new EncryptCookiesExcludesCheck($this->app))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toContain("'auth_session'");
});

it('reports a cookie once when both the $except property and bootstrap/app.php list it', function () {
    $kernel = $this->app->make(Kernel::class);
    (new ReflectionClass($kernel))->getProperty('middlewareGroups')->setValue($kernel, [
        'web' => [EncryptCookies::class, AppEncryptCookies::class],
    ]);
    (new Middleware)->encryptCookies(except: ['auth_session', 'api_token']);

    $messages = array_map(
        fn ($finding) => $finding->message,
        iterator_to_array((new EncryptCookiesExcludesCheck($this->app))->run(), false),
    );

    expect($messages)->toHaveCount(2)
        ->and($messages[0])->toContain("'auth_session'")
        ->and($messages[1])->toContain("'api_token'");
});

it('reads the bootstrap/app.php list when EncryptCookies is not registered in the kernel', function () {
    $kernel = $this->app->make(Kernel::class);
    $reflection = new ReflectionClass($kernel);
    $reflection->getProperty('middlewareGroups')->setValue($kernel, ['web' => []]);
    $reflection->getProperty('middleware')->setValue($kernel, []);
    $reflection->getProperty('middlewarePriority')->setValue($kernel, []);
    (new Middleware)->encryptCookies(except: ['laravel_session']);

    expect(iterator_to_array((new EncryptCookiesExcludesCheck($this->app))->run()))->toHaveCount(1);
});

it('passes when EncryptCookies cannot be resolved', function () {
    config()->set('app.key', '');

    expect(iterator_to_array((new EncryptCookiesExcludesCheck($this->app))->run()))->toBeEmpty();
});

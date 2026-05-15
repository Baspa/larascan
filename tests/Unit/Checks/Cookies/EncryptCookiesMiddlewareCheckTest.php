<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Cookies\EncryptCookiesMiddlewareCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Cookie\Middleware\EncryptCookies;

it('exposes correct metadata', function () {
    $check = new EncryptCookiesMiddlewareCheck($this->app);

    expect($check->id())->toBe('cookies.encrypt-middleware')
        ->and($check->category())->toBe(Category::Cookies)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when EncryptCookies is in the web middleware group', function () {
    $kernel = $this->app->make(Kernel::class);
    $reflection = new ReflectionClass($kernel);
    $prop = $reflection->getProperty('middlewareGroups');
    $prop->setValue($kernel, [
        'web' => [EncryptCookies::class],
    ]);

    expect(iterator_to_array((new EncryptCookiesMiddlewareCheck($this->app))->run()))->toBeEmpty();
});

it('fails when EncryptCookies is missing from all middleware groups', function () {
    $kernel = $this->app->make(Kernel::class);
    $reflection = new ReflectionClass($kernel);

    $reflection->getProperty('middlewareGroups')->setValue($kernel, ['web' => []]);
    $reflection->getProperty('middleware')->setValue($kernel, []);
    $reflection->getProperty('middlewarePriority')->setValue($kernel, []);

    $findings = iterator_to_array((new EncryptCookiesMiddlewareCheck($this->app))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->message)->toContain('EncryptCookies');
});

<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Headers\HstsCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Http\Kernel;

it('exposes correct metadata', function () {
    $check = new HstsCheck($this->app);

    expect($check->id())->toBe('headers.hsts')
        ->and($check->category())->toBe(Category::Headers)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when an HSTS-like middleware is registered', function () {
    $kernel = $this->app->make(Kernel::class);
    $reflection = new ReflectionClass($kernel);
    $reflection->getProperty('middlewareGroups')->setValue($kernel, [
        'web' => ['App\\Http\\Middleware\\HstsHeader'],
    ]);

    expect(iterator_to_array((new HstsCheck($this->app))->run()))->toBeEmpty();
});

it('passes when SecureHeaders middleware is registered', function () {
    $kernel = $this->app->make(Kernel::class);
    $reflection = new ReflectionClass($kernel);
    $reflection->getProperty('middlewareGroups')->setValue($kernel, [
        'web' => ['Bepsvpt\\SecureHeaders\\Middleware\\SecureHeaders'],
    ]);

    expect(iterator_to_array((new HstsCheck($this->app))->run()))->toBeEmpty();
});

it('fails with downgraded severity in dev when no HSTS middleware is present', function () {
    $kernel = $this->app->make(Kernel::class);
    $reflection = new ReflectionClass($kernel);
    $reflection->getProperty('middleware')->setValue($kernel, []);
    $reflection->getProperty('middlewareGroups')->setValue($kernel, ['web' => []]);
    $reflection->getProperty('middlewarePriority')->setValue($kernel, []);

    config()->set('app.env', 'local');

    $findings = iterator_to_array((new HstsCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Info);
});

it('fails with declared severity in production', function () {
    $kernel = $this->app->make(Kernel::class);
    $reflection = new ReflectionClass($kernel);
    $reflection->getProperty('middleware')->setValue($kernel, []);
    $reflection->getProperty('middlewareGroups')->setValue($kernel, ['web' => []]);
    $reflection->getProperty('middlewarePriority')->setValue($kernel, []);

    config()->set('app.env', 'production');

    $findings = iterator_to_array((new HstsCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High);
});

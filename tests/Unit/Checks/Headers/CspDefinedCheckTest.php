<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Headers\CspDefinedCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Http\Kernel;
use Spatie\Csp\AddCspHeaders;

it('exposes correct metadata', function () {
    $check = new CspDefinedCheck($this->app);

    expect($check->id())->toBe('headers.csp-defined')
        ->and($check->category())->toBe(Category::Headers)
        ->and($check->severity())->toBe(Severity::High);
});

it('is skipped when spatie/laravel-csp is not installed', function () {
    $check = new CspDefinedCheck($this->app);
    if (class_exists(AddCspHeaders::class)) {
        $this->markTestSkipped('spatie/laravel-csp IS installed — this test only runs without it');
    }
    expect($check->isApplicable())->toBeFalse();
});

it('passes when CSP middleware is registered', function () {
    if (! class_exists(AddCspHeaders::class)) {
        $this->markTestSkipped('spatie/laravel-csp not installed');
    }

    $kernel = $this->app->make(Kernel::class);
    $reflection = new ReflectionClass($kernel);
    $reflection->getProperty('middlewareGroups')->setValue($kernel, [
        'web' => [AddCspHeaders::class],
    ]);

    expect(iterator_to_array((new CspDefinedCheck($this->app))->run()))->toBeEmpty();
});

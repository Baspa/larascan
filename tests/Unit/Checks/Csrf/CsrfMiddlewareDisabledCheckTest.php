<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Csrf\CsrfMiddlewareDisabledCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Http\Kernel;

it('exposes correct metadata', function () {
    $check = new CsrfMiddlewareDisabledCheck($this->app);

    expect($check->id())->toBe('csrf.middleware-disabled')
        ->and($check->category())->toBe(Category::Csrf)
        ->and($check->severity())->toBe(Severity::Critical)
        ->and($check->docsUrl())->toBe('https://github.com/baspa/larascan/blob/main/docs/checks/csrf/middleware-disabled.md');
});

it('passes when VerifyCsrfToken is in the web middleware group', function () {
    $kernel = $this->app->make(Kernel::class);
    $reflection = new ReflectionClass($kernel);
    $reflection->getProperty('middlewareGroups')->setValue($kernel, [
        'web' => ['App\\Http\\Middleware\\VerifyCsrfToken'],
    ]);

    expect(iterator_to_array((new CsrfMiddlewareDisabledCheck($this->app))->run()))->toBeEmpty();
});

it('fails when VerifyCsrfToken is missing from all middleware structures', function () {
    $kernel = $this->app->make(Kernel::class);
    $reflection = new ReflectionClass($kernel);

    $reflection->getProperty('middlewareGroups')->setValue($kernel, ['web' => []]);
    $reflection->getProperty('middleware')->setValue($kernel, []);
    $reflection->getProperty('middlewarePriority')->setValue($kernel, []);

    $findings = iterator_to_array((new CsrfMiddlewareDisabledCheck($this->app))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('csrf.middleware-disabled')
        ->and($findings[0]->message)->toContain('VerifyCsrfToken middleware is not registered');
});

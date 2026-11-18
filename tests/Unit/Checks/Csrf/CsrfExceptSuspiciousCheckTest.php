<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Csrf\CsrfExceptSuspiciousCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Baspa\Larascan\Tests\Fixtures\Middleware\AppVerifyCsrfToken;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;

beforeEach(function () {
    config()->set('app.key', 'base64:fJjK9p8wQYJxhmKQYr8MwhYrnX1z3vKzpW9rh4vF8rA=');
    PreventRequestForgery::flushState();
});

afterEach(function () {
    PreventRequestForgery::flushState();
});

it('exposes correct metadata', function () {
    $check = new CsrfExceptSuspiciousCheck($this->app);

    expect($check->id())->toBe('csrf.except-suspicious')
        ->and($check->category())->toBe(Category::Csrf)
        ->and($check->severity())->toBe(Severity::Medium)
        ->and($check->docsUrl())->toBe('https://github.com/baspa/larascan/blob/main/docs/checks/csrf/except-suspicious.md');
});

it('is applicable when the framework CSRF middleware exists', function () {
    expect((new CsrfExceptSuspiciousCheck($this->app))->isApplicable())->toBeTrue();
});

it('passes when the bootstrap/app.php except list contains only specific paths', function () {
    (new Middleware)->preventRequestForgery(except: ['/webhook/stripe', '/webhook/github']);

    expect(iterator_to_array((new CsrfExceptSuspiciousCheck($this->app))->run()))->toBeEmpty();
});

it('fails when the bootstrap/app.php except list contains a wildcard pattern', function (Closure $configure) {
    $configure(new Middleware);

    $findings = iterator_to_array((new CsrfExceptSuspiciousCheck($this->app))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->checkId)->toBe('csrf.except-suspicious')
        ->and($findings[0]->message)->toContain("'/admin/*'");
})->with([
    'preventRequestForgery()' => [fn (Middleware $middleware) => $middleware->preventRequestForgery(except: ['/admin/*', '/webhook/stripe'])],
    'validateCsrfTokens()' => [fn (Middleware $middleware) => $middleware->validateCsrfTokens(except: ['/admin/*', '/webhook/stripe'])],
]);

it('fails when an app middleware extending VerifyCsrfToken has a wildcard in its $except property', function () {
    $kernel = $this->app->make(Kernel::class);
    (new ReflectionClass($kernel))->getProperty('middlewareGroups')->setValue($kernel, [
        'web' => [AppVerifyCsrfToken::class],
    ]);

    $findings = iterator_to_array((new CsrfExceptSuspiciousCheck($this->app))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toContain("'/admin/*'");
});

it('reports an entry once when both the $except property and bootstrap/app.php list it', function () {
    $kernel = $this->app->make(Kernel::class);
    (new ReflectionClass($kernel))->getProperty('middlewareGroups')->setValue($kernel, [
        'web' => [PreventRequestForgery::class, AppVerifyCsrfToken::class],
    ]);
    (new Middleware)->preventRequestForgery(except: ['/admin/*', '/api/*']);

    $messages = array_map(
        fn ($finding) => $finding->message,
        iterator_to_array((new CsrfExceptSuspiciousCheck($this->app))->run(), false),
    );

    expect($messages)->toHaveCount(2)
        ->and($messages[0])->toContain("'/admin/*'")
        ->and($messages[1])->toContain("'/api/*'");
});

it('reads the bootstrap/app.php list when no CSRF middleware is registered in the kernel', function () {
    $kernel = $this->app->make(Kernel::class);
    $reflection = new ReflectionClass($kernel);
    $reflection->getProperty('middlewareGroups')->setValue($kernel, ['web' => []]);
    $reflection->getProperty('middleware')->setValue($kernel, []);
    $reflection->getProperty('middlewarePriority')->setValue($kernel, []);
    (new Middleware)->preventRequestForgery(except: ['/admin/*']);

    expect(iterator_to_array((new CsrfExceptSuspiciousCheck($this->app))->run()))->toHaveCount(1);
});

it('passes when the CSRF middleware cannot be resolved', function () {
    config()->set('app.key', '');

    expect(iterator_to_array((new CsrfExceptSuspiciousCheck($this->app))->run()))->toBeEmpty();
});

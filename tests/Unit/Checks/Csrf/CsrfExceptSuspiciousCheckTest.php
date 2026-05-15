<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Csrf\CsrfExceptSuspiciousCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new CsrfExceptSuspiciousCheck($this->app);

    expect($check->id())->toBe('csrf.except-suspicious')
        ->and($check->category())->toBe(Category::Csrf)
        ->and($check->severity())->toBe(Severity::Medium)
        ->and($check->docsUrl())->toBe('https://github.com/baspa/larascan/blob/main/docs/checks/csrf/except-suspicious.md');
});

it('is not applicable when VerifyCsrfToken is missing', function () {
    if (class_exists('Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken')) {
        $this->markTestSkipped('VerifyCsrfToken class exists in this Laravel version.');
    }

    $check = new CsrfExceptSuspiciousCheck($this->app);
    expect($check->isApplicable())->toBeFalse();
});

it('passes when except list contains only specific paths', function () {
    if (! class_exists('Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken')) {
        $this->markTestSkipped('VerifyCsrfToken class is not available in this Laravel version.');
    }

    config()->set('app.key', 'base64:fJjK9p8wQYJxhmKQYr8MwhYrnX1z3vKzpW9rh4vF8rA=');

    try {
        $middleware = $this->app->make('Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken');
    } catch (Throwable $e) {
        $this->markTestSkipped('VerifyCsrfToken cannot be resolved from the container: '.$e->getMessage());
    }

    $reflection = new ReflectionClass($middleware);
    if (! $reflection->hasProperty('except')) {
        $this->markTestSkipped('VerifyCsrfToken has no $except property in this Laravel version.');
    }
    $prop = $reflection->getProperty('except');
    $prop->setValue($middleware, ['/webhook/stripe', '/webhook/github']);

    $this->app->instance('Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken', $middleware);

    $findings = iterator_to_array((new CsrfExceptSuspiciousCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails when except list contains a wildcard pattern', function () {
    if (! class_exists('Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken')) {
        $this->markTestSkipped('VerifyCsrfToken class is not available in this Laravel version.');
    }

    config()->set('app.key', 'base64:fJjK9p8wQYJxhmKQYr8MwhYrnX1z3vKzpW9rh4vF8rA=');

    try {
        $middleware = $this->app->make('Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken');
    } catch (Throwable $e) {
        $this->markTestSkipped('VerifyCsrfToken cannot be resolved from the container: '.$e->getMessage());
    }

    $reflection = new ReflectionClass($middleware);
    if (! $reflection->hasProperty('except')) {
        $this->markTestSkipped('VerifyCsrfToken has no $except property in this Laravel version.');
    }
    $prop = $reflection->getProperty('except');
    $prop->setValue($middleware, ['/admin/*', '/webhook/stripe']);

    $this->app->instance('Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken', $middleware);

    $findings = iterator_to_array((new CsrfExceptSuspiciousCheck($this->app))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->checkId)->toBe('csrf.except-suspicious')
        ->and($findings[0]->message)->toContain("'/admin/*'");
});

<?php

declare(strict_types=1);

use Baspa\Larascan\Support\MiddlewareIntrospection;
use Baspa\Larascan\Tests\Fixtures\Middleware\AppPolicyTweaks;
use Baspa\Larascan\Tests\Fixtures\Middleware\PolicyMiddleware;
use Baspa\Larascan\Tests\Fixtures\Middleware\SecurityHeaders;
use Illuminate\Contracts\Http\Kernel;

it('returns flat list of FQCNs from middleware groups', function () {
    $kernel = $this->app->make(Kernel::class);
    $reflection = new ReflectionClass($kernel);
    $reflection->getProperty('middlewareGroups')->setValue($kernel, [
        'web' => ['App\\Http\\Middleware\\Foo', 'App\\Http\\Middleware\\Bar'],
        'api' => ['App\\Http\\Middleware\\Throttle'],
    ]);

    $names = MiddlewareIntrospection::listMiddlewareFqcns($this->app);
    expect($names)->toContain('App\\Http\\Middleware\\Foo')
        ->toContain('App\\Http\\Middleware\\Bar')
        ->toContain('App\\Http\\Middleware\\Throttle');
});

it('matches by case-insensitive substring', function () {
    $kernel = $this->app->make(Kernel::class);
    $reflection = new ReflectionClass($kernel);
    $reflection->getProperty('middlewareGroups')->setValue($kernel, [
        'web' => ['Spatie\\Csp\\AddCspHeaders'],
    ]);

    expect(MiddlewareIntrospection::anyMatching($this->app, ['CspHeaders']))->toBeTrue()
        ->and(MiddlewareIntrospection::anyMatching($this->app, ['nonexistent']))->toBeFalse();
});

it('returns empty array when kernel cannot be resolved', function () {
    $fakeApp = new class
    {
        public function make(string $abstract): never
        {
            throw new RuntimeException('cannot resolve');
        }
    };

    expect(MiddlewareIntrospection::listMiddlewareFqcns($fakeApp))->toBeEmpty();
});

it('matches a registered subclass whose name shares nothing with its parent', function () {
    $kernel = $this->app->make(Kernel::class);
    $reflection = new ReflectionClass($kernel);
    $reflection->getProperty('middlewareGroups')->setValue($kernel, [
        'web' => [AppPolicyTweaks::class],
    ]);

    expect(MiddlewareIntrospection::anyMatching($this->app, ['PolicyMiddleware']))->toBeFalse()
        ->and(MiddlewareIntrospection::anySubclassOf($this->app, PolicyMiddleware::class))->toBeTrue();
});

it('does not match an unrelated middleware as a subclass', function () {
    $kernel = $this->app->make(Kernel::class);
    $reflection = new ReflectionClass($kernel);
    $reflection->getProperty('middlewareGroups')->setValue($kernel, [
        'web' => [SecurityHeaders::class],
    ]);

    expect(MiddlewareIntrospection::anySubclassOf($this->app, PolicyMiddleware::class))->toBeFalse();
});

it('tolerates parameters and classes that do not exist', function () {
    $kernel = $this->app->make(Kernel::class);
    $reflection = new ReflectionClass($kernel);
    $reflection->getProperty('middlewareGroups')->setValue($kernel, [
        'web' => [AppPolicyTweaks::class.':loose', 'App\\Http\\Middleware\\DoesNotExist'],
    ]);

    expect(MiddlewareIntrospection::anySubclassOf($this->app, PolicyMiddleware::class))->toBeTrue()
        ->and(MiddlewareIntrospection::anyMentioningInSource($this->app, 'Strict-Transport-Security'))->toBeFalse();
});

it('finds a header name in the source of a registered middleware', function () {
    $kernel = $this->app->make(Kernel::class);
    $reflection = new ReflectionClass($kernel);
    $reflection->getProperty('middlewareGroups')->setValue($kernel, [
        'web' => [SecurityHeaders::class],
    ]);

    expect(MiddlewareIntrospection::anyMentioningInSource($this->app, 'Strict-Transport-Security'))->toBeTrue()
        ->and(MiddlewareIntrospection::anyMentioningInSource($this->app, 'X-Frame-Options'))->toBeFalse();
});

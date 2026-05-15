<?php

declare(strict_types=1);

use Baspa\Larascan\Support\MiddlewareIntrospection;
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

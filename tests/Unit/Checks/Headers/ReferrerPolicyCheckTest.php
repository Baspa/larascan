<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Headers\ReferrerPolicyCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Http\Kernel;

it('exposes correct metadata', function () {
    $check = new ReferrerPolicyCheck($this->app);

    expect($check->id())->toBe('headers.referrer-policy')
        ->and($check->category())->toBe(Category::Headers)
        ->and($check->severity())->toBe(Severity::Low);
});

it('passes when matching middleware is registered', function () {
    $kernel = $this->app->make(Kernel::class);
    $reflection = new ReflectionClass($kernel);
    $reflection->getProperty('middlewareGroups')->setValue($kernel, [
        'web' => ['App\\Http\\Middleware\\ReferrerPolicyHeader'],
    ]);

    expect(iterator_to_array((new ReferrerPolicyCheck($this->app))->run()))->toBeEmpty();
});

it('fails when no matching middleware is present', function () {
    $kernel = $this->app->make(Kernel::class);
    $reflection = new ReflectionClass($kernel);
    $reflection->getProperty('middleware')->setValue($kernel, []);
    $reflection->getProperty('middlewareGroups')->setValue($kernel, ['web' => []]);
    $reflection->getProperty('middlewarePriority')->setValue($kernel, []);

    $findings = iterator_to_array((new ReferrerPolicyCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Low);
});

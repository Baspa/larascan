<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Headers\CspUnsafeInlineCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Spatie\Csp\AddCspHeaders;

it('exposes correct metadata', function () {
    $check = new CspUnsafeInlineCheck($this->app);

    expect($check->id())->toBe('headers.csp-unsafe-inline')
        ->and($check->category())->toBe(Category::Headers)
        ->and($check->severity())->toBe(Severity::Medium);
});

it('is skipped when spatie/laravel-csp is not installed', function () {
    if (class_exists(AddCspHeaders::class)) {
        $this->markTestSkipped('spatie/laravel-csp IS installed — this test only runs without it');
    }
    expect((new CspUnsafeInlineCheck($this->app))->isApplicable())->toBeFalse();
});

it('passes when no csp config exists', function () {
    if (! class_exists(AddCspHeaders::class)) {
        $this->markTestSkipped('spatie/laravel-csp not installed');
    }
    config()->set('csp', null);
    expect(iterator_to_array((new CspUnsafeInlineCheck($this->app))->run()))->toBeEmpty();
});

it('fails when policy contains unsafe-inline', function () {
    if (! class_exists(AddCspHeaders::class)) {
        $this->markTestSkipped('spatie/laravel-csp not installed');
    }
    config()->set('csp.policy', "default-src 'self' 'unsafe-inline'");

    $findings = iterator_to_array((new CspUnsafeInlineCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium);
});

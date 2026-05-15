<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Headers\CorsWildcardCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new CorsWildcardCheck($this->app);

    expect($check->id())->toBe('headers.cors-wildcard')
        ->and($check->category())->toBe(Category::Headers)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when cors config is absent', function () {
    config()->set('cors', null);
    expect(iterator_to_array((new CorsWildcardCheck($this->app))->run()))->toBeEmpty();
});

it('passes when allowed_origins is wildcard but credentials is false', function () {
    config()->set('cors.allowed_origins', ['*']);
    config()->set('cors.supports_credentials', false);

    expect(iterator_to_array((new CorsWildcardCheck($this->app))->run()))->toBeEmpty();
});

it('passes when credentials true but no wildcard origin', function () {
    config()->set('cors.allowed_origins', ['https://app.example.com']);
    config()->set('cors.supports_credentials', true);

    expect(iterator_to_array((new CorsWildcardCheck($this->app))->run()))->toBeEmpty();
});

it('fails when wildcard origin combined with credentials', function () {
    config()->set('cors.allowed_origins', ['*']);
    config()->set('cors.supports_credentials', true);

    $findings = iterator_to_array((new CorsWildcardCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->message)->toContain('wildcard');
});

<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Routing\ApiHttpOnlyCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Illuminate\Support\Facades\Route;

beforeEach(function () {
    config()->set('app.url', 'http://example.test');
    config()->set('app.env', 'production');
});

it('exposes correct metadata', function () {
    $check = new ApiHttpOnlyCheck($this->app);

    expect($check->id())->toBe('routing.api-http-only')
        ->and($check->category())->toBe(Category::Routing)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when APP_URL is https regardless of route middleware', function () {
    config()->set('app.url', 'https://example.test');
    Route::get('/api/users', fn () => 'ok');

    $findings = iterator_to_array((new ApiHttpOnlyCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('passes when api route uses force.https middleware', function () {
    Route::get('/api/users', fn () => 'ok')->middleware('force.https');

    $findings = iterator_to_array((new ApiHttpOnlyCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails when api route has no https middleware and APP_URL is http', function () {
    Route::get('/api/users', fn () => 'ok');

    $findings = iterator_to_array((new ApiHttpOnlyCheck($this->app))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('routing.api-http-only');
});

it('downgrades severity to INFO outside production', function () {
    config()->set('app.env', 'local');
    Route::get('/api/users', fn () => 'ok');

    $findings = iterator_to_array((new ApiHttpOnlyCheck($this->app))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Info);
});

it('ignores non-api routes', function () {
    Route::get('/dashboard', fn () => 'ok');

    $findings = iterator_to_array((new ApiHttpOnlyCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

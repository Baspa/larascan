<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Auth\RegistrationRateLimitCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Illuminate\Support\Facades\Route;

beforeEach(function () {
    config()->set('app.env', 'production');
});

it('exposes correct metadata', function () {
    $check = new RegistrationRateLimitCheck($this->app);

    expect($check->id())->toBe('auth.registration-rate-limit')
        ->and($check->category())->toBe(Category::Auth)
        ->and($check->severity())->toBe(Severity::Medium);
});

it('passes when no registration route exists', function () {
    Route::get('/dashboard', fn () => 'ok');

    $findings = iterator_to_array((new RegistrationRateLimitCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('passes when registration route is throttled', function () {
    Route::post('/register', fn () => 'ok')->name('register')->middleware('throttle:5,1');

    $findings = iterator_to_array((new RegistrationRateLimitCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails when registration route has no throttle', function () {
    Route::post('/register', fn () => 'ok')->name('register');

    $findings = iterator_to_array((new RegistrationRateLimitCheck($this->app))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->checkId)->toBe('auth.registration-rate-limit');
});

it('downgrades severity outside production', function () {
    config()->set('app.env', 'local');
    Route::post('/register', fn () => 'ok')->name('register');

    $findings = iterator_to_array((new RegistrationRateLimitCheck($this->app))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Info);
});

it('fails on /signup URI', function () {
    Route::post('/signup', fn () => 'ok');

    $findings = iterator_to_array((new RegistrationRateLimitCheck($this->app))->run());
    expect($findings)->toHaveCount(1);
});

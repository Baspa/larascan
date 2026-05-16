<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Auth\OtpRateLimitingCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Illuminate\Support\Facades\Route;

it('exposes correct metadata', function () {
    $check = new OtpRateLimitingCheck($this->app);

    expect($check->id())->toBe('auth.otp-rate-limiting')
        ->and($check->category())->toBe(Category::Auth)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when no OTP routes exist', function () {
    Route::get('/dashboard', fn () => 'ok');

    $findings = iterator_to_array((new OtpRateLimitingCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('passes when OTP route has throttle middleware', function () {
    Route::post('/two-factor/verify', fn () => 'ok')->middleware('throttle:6,1');

    $findings = iterator_to_array((new OtpRateLimitingCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails when OTP route has no throttle middleware', function () {
    Route::post('/two-factor/verify', fn () => 'ok');

    $findings = iterator_to_array((new OtpRateLimitingCheck($this->app))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('auth.otp-rate-limiting')
        ->and($findings[0]->message)->toContain('two-factor');
});

it('fails on /otp/verify pattern', function () {
    Route::post('/otp/verify', fn () => 'ok');

    $findings = iterator_to_array((new OtpRateLimitingCheck($this->app))->run());
    expect($findings)->toHaveCount(1);
});

it('ignores email verification routes', function () {
    Route::get('/email/verify/{id}/{hash}', fn () => 'ok')->name('verification.verify');

    $findings = iterator_to_array((new OtpRateLimitingCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

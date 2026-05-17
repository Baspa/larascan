<?php

declare(strict_types=1);

use Baspa\Larascan\Advices\Auth\PasswordResetMfaAdvice;
use Baspa\Larascan\Support\AdviceStatus;
use Baspa\Larascan\Support\Category;
use Illuminate\Support\Facades\Route;

it('exposes correct metadata', function () {
    $advice = new PasswordResetMfaAdvice($this->app);

    expect($advice->id())->toBe('advise.password-reset-mfa')
        ->and($advice->category())->toBe(Category::Auth);
});

it('does not surface when no password reset route exists', function () {
    Route::get('/dashboard', fn () => 'ok');

    $outcome = (new PasswordResetMfaAdvice($this->app))->run();
    expect($outcome->status)->toBe(AdviceStatus::NotSurfaced);
});

it('does not surface when password reset has MFA middleware', function () {
    Route::post('/password/reset', fn () => 'ok')->name('password.update')->middleware('two-factor');

    $outcome = (new PasswordResetMfaAdvice($this->app))->run();
    expect($outcome->status)->toBe(AdviceStatus::NotSurfaced);
});

it('surfaces when password reset has no MFA middleware', function () {
    Route::post('/password/reset', fn () => 'ok')->name('password.update');

    $outcome = (new PasswordResetMfaAdvice($this->app))->run();

    expect($outcome->status)->toBe(AdviceStatus::Surfaced)
        ->and($outcome->evidence)->toHaveCount(1);
});

it('treats fortify verified middleware as MFA-eligible', function () {
    Route::post('/password/reset', fn () => 'ok')->name('password.update')->middleware('verified');

    $outcome = (new PasswordResetMfaAdvice($this->app))->run();
    expect($outcome->status)->toBe(AdviceStatus::NotSurfaced);
});

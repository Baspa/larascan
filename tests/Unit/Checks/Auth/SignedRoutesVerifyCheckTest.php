<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Auth\SignedRoutesVerifyCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Illuminate\Support\Facades\Route;

it('exposes correct metadata', function () {
    $check = new SignedRoutesVerifyCheck($this->app);

    expect($check->id())->toBe('auth.signed-routes-verify')
        ->and($check->category())->toBe(Category::Auth)
        ->and($check->severity())->toBe(Severity::Low)
        ->and($check->docsUrl())->toBe('https://github.com/baspa/larascan/blob/main/docs/checks/auth/signed-routes-verify.md');
});

it('passes when there are no verify routes', function () {
    $findings = iterator_to_array((new SignedRoutesVerifyCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('passes when the verify email route has the signed middleware', function () {
    Route::get('/email/verify/{id}/{hash}', fn () => 'ok')
        ->name('verification.verify')
        ->middleware(['signed']);

    $findings = iterator_to_array((new SignedRoutesVerifyCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails when the verify email route lacks the signed middleware', function () {
    Route::get('/email/verify/{id}/{hash}', fn () => 'ok')
        ->name('verification.verify');

    $findings = iterator_to_array((new SignedRoutesVerifyCheck($this->app))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Low)
        ->and($findings[0]->checkId)->toBe('auth.signed-routes-verify')
        ->and($findings[0]->message)->toContain('verification.verify')
        ->and($findings[0]->message)->toContain('signed');
});

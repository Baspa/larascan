<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Auth\LoginThrottleCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Illuminate\Support\Facades\Route;

it('exposes correct metadata', function () {
    $check = new LoginThrottleCheck($this->app);

    expect($check->id())->toBe('auth.login-throttle')
        ->and($check->category())->toBe(Category::Auth)
        ->and($check->severity())->toBe(Severity::High)
        ->and($check->docsUrl())->toBe('https://github.com/baspa/larascan/blob/main/docs/checks/auth/login-throttle.md');
});

it('passes when there are no login routes', function () {
    $findings = iterator_to_array((new LoginThrottleCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('passes when the login route has throttle middleware', function () {
    Route::post('/login', fn () => 'ok')->middleware('throttle:5,1');

    $findings = iterator_to_array((new LoginThrottleCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails when the login route lacks throttle middleware', function () {
    Route::post('/login', fn () => 'ok');

    $findings = iterator_to_array((new LoginThrottleCheck($this->app))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('auth.login-throttle')
        ->and($findings[0]->message)->toContain('login')
        ->and($findings[0]->message)->toContain('throttle');
});

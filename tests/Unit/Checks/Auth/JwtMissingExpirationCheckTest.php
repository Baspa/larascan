<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Auth\JwtMissingExpirationCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new JwtMissingExpirationCheck($this->app);

    expect($check->id())->toBe('auth.jwt-missing-expiration')
        ->and($check->category())->toBe(Category::Auth)
        ->and($check->severity())->toBe(Severity::High);
});

it('is not applicable when tymon/jwt-auth is not installed', function () {
    $check = new JwtMissingExpirationCheck($this->app);
    expect($check->isApplicable())->toBeFalse();
});

it('yields no findings when not applicable (gate protects run)', function () {
    config()->set('jwt.ttl', null);
    $findings = iterator_to_array((new JwtMissingExpirationCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

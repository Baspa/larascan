<?php

declare(strict_types=1);

use Baspa\Larascan\Probes\CookieFlagsProbe;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\Severity;

function cookieContext(array $cookies, bool $isHttps = true, bool $isLocal = false): ProbeContext
{
    return new ProbeContext(
        url: 'https://example.com',
        isHttps: $isHttps,
        isLocal: $isLocal,
        status: 200,
        cookies: $cookies,
    );
}

it('passes a fully-flagged secure session cookie', function () {
    $context = cookieContext([
        ['name' => 'laravel_session', 'secure' => true, 'httponly' => true, 'samesite' => 'lax'],
    ]);

    expect(iterator_to_array((new CookieFlagsProbe)->evaluate($context)))->toBeEmpty();
});

it('flags missing Secure on https as High', function () {
    $context = cookieContext([
        ['name' => 'xsrf', 'secure' => false, 'httponly' => false, 'samesite' => 'lax'],
    ]);
    $findings = iterator_to_array((new CookieFlagsProbe)->evaluate($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High);
});

it('flags missing HttpOnly on the session cookie as High', function () {
    $context = cookieContext([
        ['name' => 'my_app_session', 'secure' => true, 'httponly' => false, 'samesite' => 'lax'],
    ]);
    $findings = iterator_to_array((new CookieFlagsProbe)->evaluate($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High);
});

it('flags missing SameSite as Medium', function () {
    $context = cookieContext([
        ['name' => 'xsrf', 'secure' => true, 'httponly' => true, 'samesite' => null],
    ]);
    $findings = iterator_to_array((new CookieFlagsProbe)->evaluate($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium);
});

it('evaluates multiple Set-Cookie headers independently', function () {
    $context = cookieContext([
        ['name' => 'laravel_session', 'secure' => false, 'httponly' => false, 'samesite' => null],
        ['name' => 'remember', 'secure' => true, 'httponly' => true, 'samesite' => 'strict'],
    ]);
    $findings = iterator_to_array((new CookieFlagsProbe)->evaluate($context));

    // Missing Secure (High), missing HttpOnly on session (High), missing SameSite (Medium).
    expect($findings)->toHaveCount(3);
});

it('does not flag missing Secure for an http target', function () {
    $context = cookieContext([
        ['name' => 'session', 'secure' => false, 'httponly' => true, 'samesite' => 'lax'],
    ], isHttps: false);

    expect(iterator_to_array((new CookieFlagsProbe)->evaluate($context)))->toBeEmpty();
});

it('downgrades to Info for local targets', function () {
    $context = cookieContext([
        ['name' => 'laravel_session', 'secure' => false, 'httponly' => false, 'samesite' => null],
    ], isHttps: true, isLocal: true);
    $findings = iterator_to_array((new CookieFlagsProbe)->evaluate($context));

    foreach ($findings as $f) {
        expect($f->severity)->toBe(Severity::Info);
    }
});

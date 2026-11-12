<?php

declare(strict_types=1);

use Baspa\Larascan\Support\ProbeContextFactory;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;

beforeEach(function () {
    Http::preventStrayRequests();
});

it('lower-cases header names and exposes them via the context', function () {
    Http::fake([
        'https://example.com' => Http::response('', 200, [
            'Strict-Transport-Security' => 'max-age=31536000',
            'X-Frame-Options' => 'DENY',
        ]),
        'http://example.com' => Http::response('', 200, []),
    ]);

    $context = (new ProbeContextFactory)->fromUrl('https://example.com', 5, false);

    expect($context->hasHeader('strict-transport-security'))->toBeTrue()
        ->and($context->header('Strict-Transport-Security'))->toBe('max-age=31536000')
        ->and($context->header('x-frame-options'))->toBe('DENY')
        ->and($context->isHttps)->toBeTrue()
        ->and($context->isLocal)->toBeFalse()
        ->and($context->status)->toBe(200);
});

it('parses Set-Cookie headers into structured cookies', function () {
    Http::fake([
        'https://example.com' => Http::response('', 200, [
            'Set-Cookie' => [
                'laravel_session=abc; path=/; Secure; HttpOnly; SameSite=Lax',
                'xsrf=def; path=/',
            ],
        ]),
        'http://example.com' => Http::response('', 301, ['Location' => 'https://example.com/']),
    ]);

    $context = (new ProbeContextFactory)->fromUrl('https://example.com', 5, false);

    expect($context->cookies)->toHaveCount(2)
        ->and($context->cookies[0])->toMatchArray([
            'name' => 'laravel_session',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ])
        ->and($context->cookies[1])->toMatchArray([
            'name' => 'xsrf',
            'secure' => false,
            'httponly' => false,
            'samesite' => null,
        ]);
});

it('parses cookies regardless of the Set-Cookie header casing', function () {
    Http::fake([
        'https://example.com' => Http::response('', 200, [
            'Set-cookie' => 'laravel_session=abc; path=/; Secure; HttpOnly; SameSite=Lax',
        ]),
        'http://example.com' => Http::response('', 301, ['Location' => 'https://example.com/']),
    ]);

    $context = (new ProbeContextFactory)->fromUrl('https://example.com', 5, false);

    expect($context->cookies)->toHaveCount(1)
        ->and($context->cookies[0])->toMatchArray([
            'name' => 'laravel_session',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
});

it('captures the http redirect for an https target', function () {
    Http::fake([
        'https://example.com' => Http::response('', 200, []),
        'http://example.com' => Http::response('', 301, ['Location' => 'https://example.com/']),
    ]);

    $context = (new ProbeContextFactory)->fromUrl('https://example.com', 5, false);

    expect($context->httpRedirect)->toMatchArray([
        'status' => 301,
        'location' => 'https://example.com/',
    ]);
});

it('leaves httpRedirect null for an http target', function () {
    Http::fake([
        'http://example.test' => Http::response('', 200, []),
    ]);

    $context = (new ProbeContextFactory)->fromUrl('http://example.test', 5, false);

    expect($context->httpRedirect)->toBeNull()
        ->and($context->isHttps)->toBeFalse()
        ->and($context->isLocal)->toBeTrue();
});

it('treats localhost as local', function () {
    Http::fake([
        'https://localhost' => Http::response('', 200, []),
        'http://localhost' => Http::response('', 200, []),
    ]);

    $context = (new ProbeContextFactory)->fromUrl('https://localhost', 5, false);

    expect($context->isLocal)->toBeTrue();
});

it('does not treat a non-local plain-HTTP host as local', function () {
    Http::fake([
        'http://example.com' => Http::response('', 200, []),
    ]);

    $context = (new ProbeContextFactory)->fromUrl('http://example.com', 5, false);

    expect($context->isHttps)->toBeFalse()
        ->and($context->isLocal)->toBeFalse();
});

it('treats a .test host as local even over http', function () {
    Http::fake([
        'http://foo.test' => Http::response('', 200, []),
    ]);

    $context = (new ProbeContextFactory)->fromUrl('http://foo.test', 5, false);

    expect($context->isLocal)->toBeTrue();
});

it('treats 127.0.0.1 as local', function () {
    Http::fake([
        'https://127.0.0.1' => Http::response('', 200, []),
        'http://127.0.0.1' => Http::response('', 200, []),
    ]);

    $context = (new ProbeContextFactory)->fromUrl('https://127.0.0.1', 5, false);

    expect($context->isLocal)->toBeTrue();
});

it('treats a .local host as local', function () {
    Http::fake([
        'http://printer.local' => Http::response('', 200, []),
    ]);

    $context = (new ProbeContextFactory)->fromUrl('http://printer.local', 5, false);

    expect($context->isLocal)->toBeTrue();
});

it('skips TLS verification when probing insecurely', function () {
    Http::fake([
        'https://self-signed.example' => Http::response('', 200, ['X-Frame-Options' => 'DENY']),
        'http://self-signed.example' => Http::response('', 200, []),
    ]);

    $context = (new ProbeContextFactory)->fromUrl('https://self-signed.example', 5, true);

    expect($context->status)->toBe(200)
        ->and($context->header('x-frame-options'))->toBe('DENY');

    // Both the main request and the http-redirect probe must run without verifying.
    Http::assertSent(fn ($request) => $request->url() === 'https://self-signed.example');
    Http::assertSent(fn ($request) => $request->url() === 'http://self-signed.example');
});

it('leaves httpRedirect null when the http redirect probe throws', function () {
    Http::fake([
        'https://example.com' => Http::response('', 200, []),
        'http://example.com' => fn () => throw new ConnectionException('refused'),
    ]);

    $context = (new ProbeContextFactory)->fromUrl('https://example.com', 5, false);

    expect($context->httpRedirect)->toBeNull()
        ->and($context->status)->toBe(200);
});

it('never sends URL credentials on the plain-http redirect request', function () {
    Http::fake(fn ($request) => str_starts_with($request->url(), 'https://')
        ? Http::response('', 200, [])
        : Http::response('', 301, ['Location' => 'https://example.com/']));

    $context = (new ProbeContextFactory)->fromUrl('https://deploy:secret@example.com/app', 5, false);

    expect($context->httpRedirect)->toMatchArray(['status' => 301]);

    Http::assertSent(fn ($request) => $request->url() === 'http://example.com/app');
    Http::assertNotSent(fn ($request) => str_starts_with($request->url(), 'http://')
        && (str_contains($request->url(), '@') || $request->hasHeader('Authorization')));
});

it('strips userinfo from URLs and leaves others untouched', function (string $input, string $expected) {
    expect(ProbeContextFactory::stripUserInfo($input))->toBe($expected);
})->with([
    'user and password' => ['https://user:pass@example.com/a?b=c@d', 'https://example.com/a?b=c@d'],
    'user only' => ['https://user@example.com', 'https://example.com'],
    'at sign in password' => ['https://user:p@ss@example.com/', 'https://example.com/'],
    'no userinfo' => ['https://example.com/path', 'https://example.com/path'],
    'at sign only in path' => ['https://example.com/@me', 'https://example.com/@me'],
    'at sign only in query' => ['https://example.com?mail=a@b.c', 'https://example.com?mail=a@b.c'],
]);

it('normalizes an empty Location header to null on the redirect capture', function () {
    Http::fake([
        'https://example.com' => Http::response('', 200, []),
        'http://example.com' => Http::response('', 301, ['Location' => '']),
    ]);

    $context = (new ProbeContextFactory)->fromUrl('https://example.com', 5, false);

    expect($context->httpRedirect)->toMatchArray([
        'status' => 301,
        'location' => null,
    ]);
});

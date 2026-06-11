<?php

declare(strict_types=1);

use Baspa\Larascan\Probes\HttpsRedirectProbe;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\Severity;

function redirectContext(?array $httpRedirect, bool $isLocal = false): ProbeContext
{
    return new ProbeContext(
        url: 'https://example.com',
        isHttps: true,
        isLocal: $isLocal,
        status: 200,
        httpRedirect: $httpRedirect,
    );
}

it('does not apply when there is no http redirect capture', function () {
    $context = redirectContext(null);

    expect((new HttpsRedirectProbe)->applies($context))->toBeFalse()
        ->and((new HttpsRedirectProbe)->skipReason())->toBe('target is not HTTPS');
});

it('applies when an http redirect was captured', function () {
    $context = redirectContext(['status' => 301, 'location' => 'https://example.com/']);

    expect((new HttpsRedirectProbe)->applies($context))->toBeTrue();
});

it('passes on a 301 to https', function () {
    $context = redirectContext(['status' => 301, 'location' => 'https://example.com/']);

    expect(iterator_to_array((new HttpsRedirectProbe)->evaluate($context)))->toBeEmpty();
});

it('passes on a 308 to https', function () {
    $context = redirectContext(['status' => 308, 'location' => 'https://example.com/']);

    expect(iterator_to_array((new HttpsRedirectProbe)->evaluate($context)))->toBeEmpty();
});

it('fails High on a 200 with no redirect', function () {
    $context = redirectContext(['status' => 200, 'location' => null]);
    $findings = iterator_to_array((new HttpsRedirectProbe)->evaluate($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High);
});

it('fails when redirect target is not https', function () {
    $context = redirectContext(['status' => 302, 'location' => 'http://example.com/login']);

    expect(iterator_to_array((new HttpsRedirectProbe)->evaluate($context)))->toHaveCount(1);
});

it('yields nothing when evaluate is called with no captured redirect', function () {
    $context = redirectContext(null);

    expect(iterator_to_array((new HttpsRedirectProbe)->evaluate($context)))->toBeEmpty();
});

it('fails when the status is not a redirect code even with an https location', function () {
    // A 200 that happens to carry an https Location is not an actual redirect.
    $context = redirectContext(['status' => 200, 'location' => 'https://example.com/']);

    expect(iterator_to_array((new HttpsRedirectProbe)->evaluate($context)))->toHaveCount(1);
});

it('downgrades to Info for local targets', function () {
    $context = redirectContext(['status' => 200, 'location' => null], isLocal: true);
    $findings = iterator_to_array((new HttpsRedirectProbe)->evaluate($context));

    expect($findings[0]->severity)->toBe(Severity::Info);
});

<?php

declare(strict_types=1);

use Baspa\Larascan\Probes\CspProbe;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\Severity;

function cspContext(array $headers): ProbeContext
{
    return new ProbeContext(
        url: 'https://example.com',
        isHttps: true,
        isLocal: false,
        status: 200,
        headers: $headers,
    );
}

it('fails Medium when CSP is missing', function () {
    $findings = iterator_to_array((new CspProbe)->evaluate(cspContext([])));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium);
});

it('fails when script-src has unguarded unsafe-inline', function () {
    $context = cspContext(['content-security-policy' => ["default-src 'self'; script-src 'self' 'unsafe-inline'"]]);
    $findings = iterator_to_array((new CspProbe)->evaluate($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium);
});

it('passes when unsafe-inline is guarded by a nonce', function () {
    $context = cspContext(['content-security-policy' => ["script-src 'self' 'unsafe-inline' 'nonce-abc123'"]]);

    expect(iterator_to_array((new CspProbe)->evaluate($context)))->toBeEmpty();
});

it('passes a strict policy without unsafe-inline', function () {
    $context = cspContext(['content-security-policy' => ["default-src 'self'; script-src 'self'"]]);

    expect(iterator_to_array((new CspProbe)->evaluate($context)))->toBeEmpty();
});

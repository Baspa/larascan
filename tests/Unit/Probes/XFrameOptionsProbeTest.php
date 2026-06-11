<?php

declare(strict_types=1);

use Baspa\Larascan\Probes\XFrameOptionsProbe;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\Severity;

function xfoContext(array $headers): ProbeContext
{
    return new ProbeContext(
        url: 'https://example.com',
        isHttps: true,
        isLocal: false,
        status: 200,
        headers: $headers,
    );
}

it('passes with X-Frame-Options DENY', function () {
    $context = xfoContext(['x-frame-options' => ['DENY']]);

    expect(iterator_to_array((new XFrameOptionsProbe)->evaluate($context)))->toBeEmpty();
});

it('passes with X-Frame-Options SAMEORIGIN', function () {
    $context = xfoContext(['x-frame-options' => ['SAMEORIGIN']]);

    expect(iterator_to_array((new XFrameOptionsProbe)->evaluate($context)))->toBeEmpty();
});

it('passes when CSP has frame-ancestors', function () {
    $context = xfoContext(['content-security-policy' => ["frame-ancestors 'self'"]]);

    expect(iterator_to_array((new XFrameOptionsProbe)->evaluate($context)))->toBeEmpty();
});

it('fails Medium with no protection', function () {
    $findings = iterator_to_array((new XFrameOptionsProbe)->evaluate(xfoContext([])));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium);
});

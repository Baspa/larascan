<?php

declare(strict_types=1);

use Baspa\Larascan\Probes\XFrameOptionsProbe;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\Severity;

function xfoContext(array $headers, bool $isLocal = false): ProbeContext
{
    return new ProbeContext(
        url: 'https://example.com',
        isHttps: true,
        isLocal: $isLocal,
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

it('passes with a lower-cased, padded sameorigin value', function () {
    $context = xfoContext(['x-frame-options' => ['  sameorigin  ']]);

    expect(iterator_to_array((new XFrameOptionsProbe)->evaluate($context)))->toBeEmpty();
});

it('fails when X-Frame-Options is an unrecognised value and CSP lacks frame-ancestors', function () {
    $context = xfoContext([
        'x-frame-options' => ['ALLOW-FROM https://example.com'],
        'content-security-policy' => ["default-src 'self'"],
    ]);

    expect(iterator_to_array((new XFrameOptionsProbe)->evaluate($context)))->toHaveCount(1);
});

it('downgrades the finding to Info for local targets', function () {
    $findings = iterator_to_array((new XFrameOptionsProbe)->evaluate(xfoContext([], isLocal: true)));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Info);
});

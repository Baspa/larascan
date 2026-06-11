<?php

declare(strict_types=1);

use Baspa\Larascan\Probes\HstsProbe;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\Severity;

function hstsContext(array $headers, bool $isHttps = true, bool $isLocal = false): ProbeContext
{
    return new ProbeContext(
        url: 'https://example.com',
        isHttps: $isHttps,
        isLocal: $isLocal,
        status: 200,
        headers: $headers,
    );
}

it('exposes correct metadata', function () {
    $probe = new HstsProbe;

    expect($probe->id())->toBe('probe.hsts')
        ->and($probe->severity())->toBe(Severity::High);
});

it('does not apply to non-HTTPS targets', function () {
    $context = hstsContext([], isHttps: false);

    expect((new HstsProbe)->applies($context))->toBeFalse()
        ->and((new HstsProbe)->skipReason())->toBe('target is not HTTPS');
});

it('fails High when HSTS header is missing', function () {
    $findings = iterator_to_array((new HstsProbe)->evaluate(hstsContext([])));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High);
});

it('flags a short max-age as Low', function () {
    $context = hstsContext(['strict-transport-security' => ['max-age=3600']]);
    $findings = iterator_to_array((new HstsProbe)->evaluate($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Low);
});

it('flags a short quoted max-age as Low', function () {
    $context = hstsContext(['strict-transport-security' => ['max-age="3600"']]);
    $findings = iterator_to_array((new HstsProbe)->evaluate($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Low);
});

it('passes with a sufficient quoted max-age', function () {
    $context = hstsContext(['strict-transport-security' => ['max-age="31536000"; includeSubDomains']]);

    expect(iterator_to_array((new HstsProbe)->evaluate($context)))->toBeEmpty();
});

it('passes with a sufficient max-age', function () {
    $context = hstsContext(['strict-transport-security' => ['max-age=31536000; includeSubDomains']]);

    expect(iterator_to_array((new HstsProbe)->evaluate($context)))->toBeEmpty();
});

it('passes when the header is present but has no parseable max-age', function () {
    // No max-age directive at all — the probe cannot judge the duration and
    // does not flag it (the regex simply does not match).
    $context = hstsContext(['strict-transport-security' => ['includeSubDomains']]);

    expect(iterator_to_array((new HstsProbe)->evaluate($context)))->toBeEmpty();
});

it('downgrades to Info for local targets', function () {
    $context = hstsContext([], isHttps: true, isLocal: true);
    $findings = iterator_to_array((new HstsProbe)->evaluate($context));

    expect($findings[0]->severity)->toBe(Severity::Info);
});

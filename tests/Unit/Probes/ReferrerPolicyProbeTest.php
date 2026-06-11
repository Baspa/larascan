<?php

declare(strict_types=1);

use Baspa\Larascan\Probes\ReferrerPolicyProbe;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\Severity;

function rpContext(array $headers): ProbeContext
{
    return new ProbeContext(
        url: 'https://example.com',
        isHttps: true,
        isLocal: false,
        status: 200,
        headers: $headers,
    );
}

it('passes with a safe policy', function () {
    $context = rpContext(['referrer-policy' => ['strict-origin-when-cross-origin']]);

    expect(iterator_to_array((new ReferrerPolicyProbe)->evaluate($context)))->toBeEmpty();
});

it('fails Low when missing', function () {
    $findings = iterator_to_array((new ReferrerPolicyProbe)->evaluate(rpContext([])));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Low);
});

it('fails when unsafe-url', function () {
    $context = rpContext(['referrer-policy' => ['unsafe-url']]);

    expect(iterator_to_array((new ReferrerPolicyProbe)->evaluate($context)))->toHaveCount(1);
});

it('fails when unsafe-url is padded and upper-cased', function () {
    $context = rpContext(['referrer-policy' => ['  UNSAFE-URL  ']]);

    expect(iterator_to_array((new ReferrerPolicyProbe)->evaluate($context)))->toHaveCount(1);
});

it('downgrades a missing-header finding to Info for local targets', function () {
    $context = new ProbeContext(
        url: 'https://app.test',
        isHttps: true,
        isLocal: true,
        status: 200,
        headers: [],
    );
    $findings = iterator_to_array((new ReferrerPolicyProbe)->evaluate($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Info);
});

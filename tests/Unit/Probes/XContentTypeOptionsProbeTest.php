<?php

declare(strict_types=1);

use Baspa\Larascan\Probes\XContentTypeOptionsProbe;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\Severity;

function xctoContext(array $headers, bool $isLocal = false): ProbeContext
{
    return new ProbeContext(
        url: 'https://example.com',
        isHttps: true,
        isLocal: $isLocal,
        status: 200,
        headers: $headers,
    );
}

it('passes when set to nosniff', function () {
    $context = xctoContext(['x-content-type-options' => ['nosniff']]);

    expect(iterator_to_array((new XContentTypeOptionsProbe)->evaluate($context)))->toBeEmpty();
});

it('fails Medium when missing', function () {
    $findings = iterator_to_array((new XContentTypeOptionsProbe)->evaluate(xctoContext([])));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium);
});

it('fails when value is not nosniff', function () {
    $context = xctoContext(['x-content-type-options' => ['sniff']]);

    expect(iterator_to_array((new XContentTypeOptionsProbe)->evaluate($context)))->toHaveCount(1);
});

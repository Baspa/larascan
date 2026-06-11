<?php

declare(strict_types=1);

use Baspa\Larascan\Probes\ServerDisclosureProbe;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\Severity;

function serverContext(array $headers): ProbeContext
{
    return new ProbeContext(
        url: 'https://example.com',
        isHttps: true,
        isLocal: false,
        status: 200,
        headers: $headers,
    );
}

it('passes with no disclosing headers', function () {
    $context = serverContext(['server' => ['nginx']]);

    expect(iterator_to_array((new ServerDisclosureProbe)->evaluate($context)))->toBeEmpty();
});

it('flags X-Powered-By', function () {
    $context = serverContext(['x-powered-by' => ['PHP/8.3.0']]);
    $findings = iterator_to_array((new ServerDisclosureProbe)->evaluate($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Low);
});

it('flags a versioned Server header', function () {
    $context = serverContext(['server' => ['nginx/1.25.3']]);
    $findings = iterator_to_array((new ServerDisclosureProbe)->evaluate($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Low);
});

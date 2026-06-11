<?php

declare(strict_types=1);

use Baspa\Larascan\Probes\ServerDisclosureProbe;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\Severity;

function serverContext(array $headers, bool $isLocal = false): ProbeContext
{
    return new ProbeContext(
        url: 'https://example.com',
        isHttps: true,
        isLocal: $isLocal,
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

it('passes with no headers at all', function () {
    expect(iterator_to_array((new ServerDisclosureProbe)->evaluate(serverContext([]))))->toBeEmpty();
});

it('flags both X-Powered-By and a versioned Server header together', function () {
    $context = serverContext([
        'x-powered-by' => ['PHP/8.3.0'],
        'server' => ['Apache/2.4.57'],
    ]);

    expect(iterator_to_array((new ServerDisclosureProbe)->evaluate($context)))->toHaveCount(2);
});

it('downgrades disclosure findings to Info for local targets', function () {
    $context = serverContext([
        'x-powered-by' => ['PHP/8.3.0'],
        'server' => ['nginx/1.25.3'],
    ], isLocal: true);
    $findings = iterator_to_array((new ServerDisclosureProbe)->evaluate($context));

    expect($findings)->toHaveCount(2);
    foreach ($findings as $f) {
        expect($f->severity)->toBe(Severity::Info);
    }
});

<?php

declare(strict_types=1);

use Baspa\Larascan\Support\AbstractProbe;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\Severity;

/**
 * A minimal probe that relies entirely on AbstractProbe's defaults — it does
 * not override applies(), skipReason() or docsUrl().
 */
final class DefaultsProbe extends AbstractProbe
{
    public function id(): string
    {
        return 'probe.defaults-example';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'Defaults example';
    }

    /** @return iterable<Finding> */
    public function evaluate(ProbeContext $context): iterable
    {
        return [];
    }

    public function exposeSeverityFor(ProbeContext $context, Severity $remote): Severity
    {
        return $this->severityFor($context, $remote);
    }
}

/**
 * A probe whose id has no dot, exercising the docsUrl() else branch.
 */
final class NoDotProbe extends AbstractProbe
{
    public function id(): string
    {
        return 'standalone';
    }

    public function severity(): Severity
    {
        return Severity::Low;
    }

    public function name(): string
    {
        return 'Standalone';
    }

    /** @return iterable<Finding> */
    public function evaluate(ProbeContext $context): iterable
    {
        return [];
    }
}

function defaultsContext(bool $isLocal = false): ProbeContext
{
    return new ProbeContext(
        url: 'https://example.com',
        isHttps: true,
        isLocal: $isLocal,
        status: 200,
    );
}

it('applies by default to any context', function () {
    expect((new DefaultsProbe)->applies(defaultsContext()))->toBeTrue();
});

it('returns an empty skip reason by default', function () {
    expect((new DefaultsProbe)->skipReason())->toBe('');
});

it('derives the docs url from the slug after the dot', function () {
    expect((new DefaultsProbe)->docsUrl())
        ->toBe('https://github.com/baspa/larascan/blob/main/docs/probes/defaults-example.md');
});

it('uses the whole id as the slug when there is no dot', function () {
    expect((new NoDotProbe)->docsUrl())
        ->toBe('https://github.com/baspa/larascan/blob/main/docs/probes/standalone.md');
});

it('keeps the remote severity for non-local targets', function () {
    expect((new DefaultsProbe)->exposeSeverityFor(defaultsContext(isLocal: false), Severity::High))
        ->toBe(Severity::High);
});

it('downgrades to Info for local targets', function () {
    expect((new DefaultsProbe)->exposeSeverityFor(defaultsContext(isLocal: true), Severity::High))
        ->toBe(Severity::Info);
});

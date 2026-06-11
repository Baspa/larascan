<?php

declare(strict_types=1);

use Baspa\Larascan\Support\AbstractProbe;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\ProbeRegistry;
use Baspa\Larascan\Support\Severity;

final class RegistryStubProbe extends AbstractProbe
{
    public function __construct(private string $id) {}

    public function id(): string
    {
        return $this->id;
    }

    public function severity(): Severity
    {
        return Severity::Low;
    }

    public function name(): string
    {
        return 'stub';
    }

    /** @return iterable<Finding> */
    public function evaluate(ProbeContext $context): iterable
    {
        return [];
    }
}

it('registers and lists probes', function () {
    $registry = new ProbeRegistry;
    $registry->register(new RegistryStubProbe('probe.a'));
    $registry->register(new RegistryStubProbe('probe.b'));

    expect($registry->all())->toHaveCount(2);
});

it('throws on duplicate registration', function () {
    $registry = new ProbeRegistry;
    $registry->register(new RegistryStubProbe('probe.a'));

    expect(fn () => $registry->register(new RegistryStubProbe('probe.a')))
        ->toThrow(InvalidArgumentException::class, 'already registered');
});

it('treats probes without explicit config as enabled', function () {
    $registry = new ProbeRegistry;
    $registry->register(new RegistryStubProbe('probe.a'));

    expect($registry->enabled())->toHaveCount(1);
});

it('excludes a probe disabled via config', function () {
    $registry = new ProbeRegistry(['probe.b' => ['enabled' => false]]);
    $registry->register(new RegistryStubProbe('probe.a'));
    $registry->register(new RegistryStubProbe('probe.b'));

    $enabled = array_map(fn ($p) => $p->id(), $registry->enabled());

    expect($enabled)->toBe(['probe.a']);
});

it('matches probes by exact id', function () {
    $registry = new ProbeRegistry;
    $registry->register(new RegistryStubProbe('probe.hsts'));
    $registry->register(new RegistryStubProbe('probe.csp'));

    $matched = array_map(fn ($p) => $p->id(), iterator_to_array($registry->matching(['probe.hsts'])));

    expect($matched)->toBe(['probe.hsts']);
});

it('matches probes by wildcard pattern', function () {
    $registry = new ProbeRegistry;
    $registry->register(new RegistryStubProbe('probe.cookie-flags'));
    $registry->register(new RegistryStubProbe('probe.csp'));
    $registry->register(new RegistryStubProbe('probe.hsts'));

    $matched = array_map(fn ($p) => $p->id(), iterator_to_array($registry->matching(['probe.c*'])));

    expect($matched)->toBe(['probe.cookie-flags', 'probe.csp']);
});

it('yields each probe at most once even when several patterns match', function () {
    $registry = new ProbeRegistry;
    $registry->register(new RegistryStubProbe('probe.hsts'));

    $matched = iterator_to_array($registry->matching(['probe.hsts', 'probe.*']));

    expect($matched)->toHaveCount(1);
});

it('yields nothing when no pattern matches', function () {
    $registry = new ProbeRegistry;
    $registry->register(new RegistryStubProbe('probe.hsts'));

    expect(iterator_to_array($registry->matching(['probe.nope'])))->toBeEmpty();
});

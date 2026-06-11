<?php

declare(strict_types=1);

use Baspa\Larascan\Prober;
use Baspa\Larascan\Support\AbstractProbe;
use Baspa\Larascan\Support\CheckStatus;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\ProbeRegistry;
use Baspa\Larascan\Support\Severity;

final class ProberStubProbe extends AbstractProbe
{
    /**
     * @param  array<int, Finding>  $findings
     */
    public function __construct(
        private string $id,
        private array $findings = [],
        private bool $applies = true,
        private string $skipReason = '',
        private ?Throwable $throw = null,
    ) {}

    public function id(): string
    {
        return $this->id;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'stub';
    }

    public function applies(ProbeContext $context): bool
    {
        return $this->applies;
    }

    public function skipReason(): string
    {
        return $this->skipReason;
    }

    /** @return iterable<Finding> */
    public function evaluate(ProbeContext $context): iterable
    {
        if ($this->throw !== null) {
            throw $this->throw;
        }

        return $this->findings;
    }
}

function proberContext(): ProbeContext
{
    return new ProbeContext(
        url: 'https://example.com',
        isHttps: true,
        isLocal: false,
        status: 200,
    );
}

it('records a probe that applies and yields nothing as Passed', function () {
    $registry = new ProbeRegistry;
    $registry->register(new ProberStubProbe('probe.pass'));

    $result = (new Prober($registry))->probe(proberContext());

    expect($result->statusOf('probe.pass'))->toBe(CheckStatus::Passed)
        ->and($result->findings())->toBeEmpty();
});

it('records a probe that yields findings as Failed', function () {
    $finding = new Finding('probe.fail', Severity::High, 'broken');
    $registry = new ProbeRegistry;
    $registry->register(new ProberStubProbe('probe.fail', findings: [$finding]));

    $result = (new Prober($registry))->probe(proberContext());

    expect($result->statusOf('probe.fail'))->toBe(CheckStatus::Failed)
        ->and($result->findings())->toHaveCount(1)
        ->and($result->findings()[0]->message)->toBe('broken');
});

it('skips a probe whose applies() is false and records the skip reason', function () {
    $registry = new ProbeRegistry;
    $registry->register(new ProberStubProbe('probe.skip', applies: false, skipReason: 'target is not HTTPS'));

    $result = (new Prober($registry))->probe(proberContext());

    expect($result->statusOf('probe.skip'))->toBe(CheckStatus::Skipped)
        ->and($result->skipReasonOf('probe.skip'))->toBe('target is not HTTPS');
});

it('records a probe whose evaluate() throws as Errored', function () {
    $registry = new ProbeRegistry;
    $registry->register(new ProberStubProbe('probe.boom', throw: new RuntimeException('kaboom')));

    $result = (new Prober($registry))->probe(proberContext());

    expect($result->statusOf('probe.boom'))->toBe(CheckStatus::Errored)
        ->and($result->errorOf('probe.boom'))->toContain('kaboom');
});

it('exposes its registry', function () {
    $registry = new ProbeRegistry;
    $prober = new Prober($registry);

    expect($prober->registry())->toBe($registry);
});

it('does not run a probe disabled via config', function () {
    $registry = new ProbeRegistry(['probe.disabled' => ['enabled' => false]]);
    $registry->register(new ProberStubProbe('probe.disabled', findings: [
        new Finding('probe.disabled', Severity::High, 'should not surface'),
    ]));

    $result = (new Prober($registry))->probe(proberContext());

    expect($result->statusOf('probe.disabled'))->toBeNull()
        ->and($result->findings())->toBeEmpty();
});

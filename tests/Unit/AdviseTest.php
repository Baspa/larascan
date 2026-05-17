<?php

declare(strict_types=1);

use Baspa\Larascan\Advise;
use Baspa\Larascan\Contracts\Advice;
use Baspa\Larascan\Support\AdviceOutcome;
use Baspa\Larascan\Support\AdviceRegistry;
use Baspa\Larascan\Support\AdviceStatus;
use Baspa\Larascan\Support\Category;

function buildAdvise(callable $configure): Advise
{
    $registry = new AdviceRegistry;
    $configure($registry);

    return new Advise($registry);
}

function makeRunningAdvice(string $id, AdviceOutcome $outcome, bool $applicable = true): Advice
{
    return new class($id, $outcome, $applicable) implements Advice
    {
        public function __construct(private string $idValue, private AdviceOutcome $outcome, private bool $applicable) {}

        public function id(): string
        {
            return $this->idValue;
        }

        public function category(): Category
        {
            return Category::Auth;
        }

        public function name(): string
        {
            return 'test';
        }

        public function isApplicable(): bool
        {
            return $this->applicable;
        }

        public function docsUrl(): string
        {
            return 'https://example.test';
        }

        public function run(): AdviceOutcome
        {
            return $this->outcome;
        }
    };
}

it('runs each enabled advice and records its outcome', function () {
    $advise = buildAdvise(function (AdviceRegistry $r) {
        $r->register(makeRunningAdvice('advise.a', AdviceOutcome::surfaced('summary')));
        $r->register(makeRunningAdvice('advise.b', AdviceOutcome::notSurfaced()));
    });

    $result = $advise->run();

    expect($result->statusOf('advise.a'))->toBe(AdviceStatus::Surfaced)
        ->and($result->statusOf('advise.b'))->toBe(AdviceStatus::NotSurfaced);
});

it('records Skipped when an advice is not applicable', function () {
    $advise = buildAdvise(function (AdviceRegistry $r) {
        $r->register(makeRunningAdvice('advise.a', AdviceOutcome::surfaced('x'), applicable: false));
    });

    $result = $advise->run();

    expect($result->statusOf('advise.a'))->toBe(AdviceStatus::Skipped);
});

it('records Errored when an advice throws', function () {
    $throwing = new class implements Advice
    {
        public function id(): string
        {
            return 'advise.throws';
        }

        public function category(): Category
        {
            return Category::Auth;
        }

        public function name(): string
        {
            return 'throws';
        }

        public function isApplicable(): bool
        {
            return true;
        }

        public function docsUrl(): string
        {
            return 'https://example.test';
        }

        public function run(): AdviceOutcome
        {
            throw new RuntimeException('boom');
        }
    };

    $advise = buildAdvise(fn (AdviceRegistry $r) => $r->register($throwing));
    $result = $advise->run();

    expect($result->statusOf('advise.throws'))->toBe(AdviceStatus::Errored)
        ->and($result->outcomeOf('advise.throws')->summary)->toContain('boom');
});

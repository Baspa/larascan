<?php

declare(strict_types=1);

use Baspa\Larascan\Support\AdviceEvidence;
use Baspa\Larascan\Support\AdviceOutcome;
use Baspa\Larascan\Support\AdviceResult;
use Baspa\Larascan\Support\AdviceStatus;

it('records advice outcomes and counts them', function () {
    $result = new AdviceResult;
    $result->record('advise.foo', AdviceOutcome::surfaced('summary', [new AdviceEvidence('x')]));
    $result->record('advise.bar', AdviceOutcome::notSurfaced());
    $result->record('advise.baz', AdviceOutcome::skipped('reason'));
    $result->record('advise.qux', AdviceOutcome::errored('boom'));

    expect($result->counts())->toBe([
        'surfaced' => 1,
        'not_surfaced' => 1,
        'skipped' => 1,
        'errored' => 1,
    ]);
});

it('returns the outcome for a specific advice', function () {
    $result = new AdviceResult;
    $outcome = AdviceOutcome::surfaced('summary');
    $result->record('advise.foo', $outcome);

    expect($result->outcomeOf('advise.foo'))->toBe($outcome)
        ->and($result->outcomeOf('advise.unknown'))->toBeNull();
});

it('returns status for a specific advice', function () {
    $result = new AdviceResult;
    $result->record('advise.foo', AdviceOutcome::skipped('x'));

    expect($result->statusOf('advise.foo'))->toBe(AdviceStatus::Skipped);
});

it('exposes an ordered list of advice ids', function () {
    $result = new AdviceResult;
    $result->record('advise.a', AdviceOutcome::notSurfaced());
    $result->record('advise.b', AdviceOutcome::notSurfaced());

    expect(array_keys($result->statuses()))->toBe(['advise.a', 'advise.b']);
});

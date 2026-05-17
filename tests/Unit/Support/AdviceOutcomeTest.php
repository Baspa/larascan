<?php

declare(strict_types=1);

use Baspa\Larascan\Support\AdviceEvidence;
use Baspa\Larascan\Support\AdviceOutcome;
use Baspa\Larascan\Support\AdviceStatus;

it('builds a surfaced outcome via the factory', function () {
    $outcome = AdviceOutcome::surfaced('found 2 things', [
        new AdviceEvidence('first', 'app/A.php', 10),
        new AdviceEvidence('second', 'app/B.php', 20),
    ]);

    expect($outcome->status)->toBe(AdviceStatus::Surfaced)
        ->and($outcome->summary)->toBe('found 2 things')
        ->and($outcome->evidence)->toHaveCount(2)
        ->and($outcome->skipReason)->toBeNull();
});

it('builds a not-surfaced outcome with no evidence', function () {
    $outcome = AdviceOutcome::notSurfaced();

    expect($outcome->status)->toBe(AdviceStatus::NotSurfaced)
        ->and($outcome->summary)->toBe('')
        ->and($outcome->evidence)->toBe([]);
});

it('builds a skipped outcome with a reason', function () {
    $outcome = AdviceOutcome::skipped('livewire not installed');

    expect($outcome->status)->toBe(AdviceStatus::Skipped)
        ->and($outcome->skipReason)->toBe('livewire not installed');
});

it('builds an errored outcome with a message', function () {
    $outcome = AdviceOutcome::errored('parser blew up');

    expect($outcome->status)->toBe(AdviceStatus::Errored)
        ->and($outcome->summary)->toBe('parser blew up');
});

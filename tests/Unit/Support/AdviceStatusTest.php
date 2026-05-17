<?php

declare(strict_types=1);

use Baspa\Larascan\Support\AdviceStatus;

it('has four expected cases', function () {
    expect(AdviceStatus::Surfaced->value)->toBe('surfaced')
        ->and(AdviceStatus::NotSurfaced->value)->toBe('not_surfaced')
        ->and(AdviceStatus::Skipped->value)->toBe('skipped')
        ->and(AdviceStatus::Errored->value)->toBe('errored');
});

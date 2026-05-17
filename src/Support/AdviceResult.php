<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

final class AdviceResult
{
    /** @var array<string, AdviceOutcome> */
    private array $outcomes = [];

    public function record(string $adviceId, AdviceOutcome $outcome): void
    {
        $this->outcomes[$adviceId] = $outcome;
    }

    public function outcomeOf(string $adviceId): ?AdviceOutcome
    {
        return $this->outcomes[$adviceId] ?? null;
    }

    public function statusOf(string $adviceId): ?AdviceStatus
    {
        return ($this->outcomes[$adviceId] ?? null)?->status;
    }

    /**
     * @return array<string, AdviceStatus>
     */
    public function statuses(): array
    {
        return array_map(fn (AdviceOutcome $o) => $o->status, $this->outcomes);
    }

    /**
     * @return array<string, AdviceOutcome>
     */
    public function outcomes(): array
    {
        return $this->outcomes;
    }

    /**
     * @return array{surfaced: int, not_surfaced: int, skipped: int, errored: int}
     */
    public function counts(): array
    {
        $counts = ['surfaced' => 0, 'not_surfaced' => 0, 'skipped' => 0, 'errored' => 0];
        foreach ($this->outcomes as $o) {
            $counts[$o->status->value]++;
        }

        return $counts;
    }
}

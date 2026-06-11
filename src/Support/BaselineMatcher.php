<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

/**
 * Mutable matcher consumed by a single scan run. Each baseline entry carries a
 * count; a finding is suppressed while its hash still has budget left, so a
 * third occurrence of a twice-baselined finding is reported as new.
 */
final class BaselineMatcher
{
    /**
     * @param  array<string, int>  $remaining  remaining occurrence counts keyed by finding hash
     */
    public function __construct(
        private array $remaining,
        private readonly FindingHasher $hasher,
    ) {}

    public function suppresses(Finding $finding): bool
    {
        $hash = $this->hasher->hash($finding);

        if (($this->remaining[$hash] ?? 0) <= 0) {
            return false;
        }

        $this->remaining[$hash]--;

        return true;
    }

    /**
     * Total baseline occurrences that no current finding matched.
     */
    public function staleCount(): int
    {
        return array_sum($this->remaining);
    }
}

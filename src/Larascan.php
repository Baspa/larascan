<?php

declare(strict_types=1);

namespace Baspa\Larascan;

use Baspa\Larascan\Contracts\Check;
use Baspa\Larascan\Support\CheckRegistry;
use Baspa\Larascan\Support\CheckStatus;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ScanOptions;
use Baspa\Larascan\Support\ScanResult;
use Throwable;

final class Larascan
{
    public function __construct(
        private readonly CheckRegistry $registry,
    ) {}

    public function registry(): CheckRegistry
    {
        return $this->registry;
    }

    public function scan(ScanOptions $options = new ScanOptions): ScanResult
    {
        $result = new ScanResult;
        $matcher = $options->baseline?->matcher();

        foreach ($this->selectChecks($options) as $check) {
            if (! $check->isApplicable()) {
                $result = $result->record($check->id(), CheckStatus::Skipped, [], 'not applicable');

                continue;
            }

            try {
                /** @var array<int, Finding> $findings */
                $findings = [];
                /** @var array<int, Finding> $baselined */
                $baselined = [];
                foreach ($check->run() as $f) {
                    if ($matcher !== null && $matcher->suppresses($f)) {
                        $baselined[] = $f;
                    } else {
                        $findings[] = $f;
                    }
                }

                $status = $findings === [] ? CheckStatus::Passed : CheckStatus::Failed;
                $result = $result->record($check->id(), $status, $findings, baselinedFindings: $baselined);
            } catch (Throwable $e) {
                // Findings yielded before the error already consumed baseline
                // matcher budget, so staleCount() can under-report on errored
                // runs (accepted, cosmetic).
                $result = $result->recordError($check->id(), $e);
            }
        }

        // Stale entries are only meaningful when the full enabled set ran;
        // a filtered run would report every out-of-scope entry as stale.
        if ($options->checkPatterns === [] && $options->category === null) {
            $result = $result->withStaleBaselineCount($matcher?->staleCount() ?? 0);
        }

        return $result;
    }

    /**
     * @return iterable<Check>
     */
    private function selectChecks(ScanOptions $options): iterable
    {
        if ($options->checkPatterns !== []) {
            return $this->registry->matching($options->checkPatterns);
        }

        if ($options->category !== null) {
            return $this->registry->forCategory($options->category);
        }

        return $this->registry->enabled();
    }
}

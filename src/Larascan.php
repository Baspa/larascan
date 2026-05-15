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

        foreach ($this->selectChecks($options) as $check) {
            if (! $check->isApplicable()) {
                $result = $result->record($check->id(), CheckStatus::Skipped, [], 'not applicable');

                continue;
            }

            try {
                /** @var array<int, Finding> $findings */
                $findings = [];
                foreach ($check->run() as $f) {
                    $findings[] = $f;
                }

                $status = $findings === [] ? CheckStatus::Passed : CheckStatus::Failed;
                $result = $result->record($check->id(), $status, $findings);
            } catch (Throwable $e) {
                $result = $result->recordError($check->id(), $e);
            }
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

<?php

declare(strict_types=1);

namespace Baspa\Larascan;

use Baspa\Larascan\Support\CheckStatus;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\ProbeRegistry;
use Baspa\Larascan\Support\ScanResult;
use Throwable;

final class Prober
{
    public function __construct(
        private readonly ProbeRegistry $registry,
    ) {}

    public function registry(): ProbeRegistry
    {
        return $this->registry;
    }

    public function probe(ProbeContext $context): ScanResult
    {
        $result = new ScanResult;

        foreach ($this->registry->enabled() as $probe) {
            if (! $probe->applies($context)) {
                $result = $result->record($probe->id(), CheckStatus::Skipped, [], $probe->skipReason());

                continue;
            }

            try {
                /** @var array<int, Finding> $findings */
                $findings = [];
                foreach ($probe->evaluate($context) as $f) {
                    $findings[] = $f;
                }

                $status = $findings === [] ? CheckStatus::Passed : CheckStatus::Failed;
                $result = $result->record($probe->id(), $status, $findings);
            } catch (Throwable $e) {
                $result = $result->recordError($probe->id(), $e);
            }
        }

        return $result;
    }
}

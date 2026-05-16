<?php

declare(strict_types=1);

namespace Baspa\Larascan;

use Baspa\Larascan\Contracts\Advice;
use Baspa\Larascan\Support\AdviceOutcome;
use Baspa\Larascan\Support\AdviceRegistry;
use Baspa\Larascan\Support\AdviceResult;
use Throwable;

final class Advise
{
    public function __construct(
        private readonly AdviceRegistry $registry,
    ) {}

    /**
     * @param  array<int, Advice>|null  $advices  optional filter; null = registry->enabled()
     */
    public function run(?array $advices = null): AdviceResult
    {
        $advices ??= $this->registry->enabled();
        $result = new AdviceResult;

        foreach ($advices as $advice) {
            if (! $advice->isApplicable()) {
                $result->record($advice->id(), AdviceOutcome::skipped('not applicable'));

                continue;
            }

            try {
                $outcome = $advice->run();
                $result->record($advice->id(), $outcome);
            } catch (Throwable $e) {
                $result->record($advice->id(), AdviceOutcome::errored($e->getMessage()));
            }
        }

        return $result;
    }
}

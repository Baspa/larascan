<?php

declare(strict_types=1);

namespace Baspa\Larascan\Commands;

use Baspa\Larascan\Advise;
use Baspa\Larascan\Contracts\Advice;
use Baspa\Larascan\Reporters\AdviceConsoleReporter;
use Baspa\Larascan\Reporters\AdviceJsonReporter;
use Baspa\Larascan\Support\AdviceRegistry;
use Baspa\Larascan\Support\AgentDetector;
use Baspa\Larascan\Support\Category;
use Illuminate\Console\Command;

class AdviseCommand extends Command
{
    protected $signature = 'larascan:advise
        {--advice=* : Filter advices by ID pattern (e.g. advise.auth.*) — repeatable}
        {--category= : Filter advices by category}
        {--format= : Output format: human (default) or json (auto-selected for agents)}';

    protected $description = 'Run larascan security advisories (heuristic, never gates CI)';

    public function handle(
        Advise $advise,
        AdviceRegistry $registry,
        AdviceConsoleReporter $consoleReporter,
    ): int {
        $advices = $this->resolveAdvices($registry);

        $result = $advise->run($advices);

        $format = $this->resolveFormat();

        if ($format === 'json') {
            (new AdviceJsonReporter)->render($result, $registry, $this->output);
        } else {
            $consoleReporter->render($result, $registry, $this->output);
        }

        return self::SUCCESS;
    }

    /**
     * @return array<int, Advice>
     */
    private function resolveAdvices(AdviceRegistry $registry): array
    {
        /** @var array<int, string> $patterns */
        $patterns = array_filter((array) $this->option('advice'), 'is_string');
        $categoryOption = $this->option('category');

        if ($patterns !== []) {
            return iterator_to_array($registry->matching($patterns), false);
        }

        if (is_string($categoryOption) && $categoryOption !== '') {
            $category = Category::tryFrom($categoryOption);
            if ($category === null) {
                $this->warn("Unknown category: {$categoryOption}");

                return [];
            }

            return iterator_to_array($registry->forCategory($category), false);
        }

        return $registry->enabled();
    }

    private function resolveFormat(): string
    {
        $option = $this->option('format');
        if (is_string($option) && in_array($option, ['human', 'json'], true)) {
            return $option;
        }

        return AgentDetector::isAgentRun() ? 'json' : 'human';
    }
}

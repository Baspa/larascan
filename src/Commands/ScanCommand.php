<?php

declare(strict_types=1);

namespace Baspa\Larascan\Commands;

use Baspa\Larascan\Larascan;
use Baspa\Larascan\Reporters\ConsoleReporter;
use Baspa\Larascan\Reporters\JsonReporter;
use Baspa\Larascan\Support\AgentDetector;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\ScanOptions;
use Baspa\Larascan\Support\Severity;
use Illuminate\Console\Command;

class ScanCommand extends Command
{
    protected $signature = 'larascan
        {--fail-on= : Severity threshold for non-zero exit code (critical|high|medium|low|info)}
        {--check=* : Filter checks by ID pattern (e.g. cookies.*) — repeatable}
        {--category= : Filter checks by category}
        {--ignore-errors : Force exit 0 even when checks error}
        {--only-failed : Hide passed and skipped checks; show only failures and errors}
        {--format= : Output format: human (default) or json (auto-selected for agents)}';

    protected $description = 'Run larascan security scan';

    public function handle(Larascan $larascan, ConsoleReporter $reporter): int
    {
        $failOnOption = $this->option('fail-on');
        $failOnConfig = config('larascan.fail_on');
        $failOnRaw = match (true) {
            is_string($failOnOption) && $failOnOption !== '' => $failOnOption,
            is_string($failOnConfig) && $failOnConfig !== '' => $failOnConfig,
            default => 'high',
        };
        $failOn = Severity::tryFrom($failOnRaw);
        if ($failOn === null) {
            $this->error("Invalid --fail-on value: {$failOnRaw}");

            return 2;
        }

        $categoryRaw = $this->option('category');
        $category = null;
        if (is_string($categoryRaw) && $categoryRaw !== '') {
            $category = Category::tryFrom($categoryRaw);
            if ($category === null) {
                $this->error("Unknown category: {$categoryRaw}");

                return 2;
            }
        }

        /** @var array<int, string> $patterns */
        $patterns = (array) $this->option('check');

        $options = new ScanOptions(
            failOn: $failOn,
            checkPatterns: $patterns,
            category: $category,
        );

        // Resolve format
        $formatOption = $this->option('format');
        $format = is_string($formatOption) && $formatOption !== ''
            ? strtolower($formatOption)
            : $this->autoFormat();

        $onlyFailed = (bool) $this->option('only-failed');

        $result = $larascan->scan($options);

        if ($format === 'json') {
            (new JsonReporter)->render($result, $this->output, onlyFailed: $onlyFailed);
        } else {
            $reporter->render($result, $this->output, onlyFailed: $onlyFailed);
        }

        $counts = $result->counts();
        if ($counts['errored'] > 0 && ! $this->option('ignore-errors')) {
            return 2;
        }

        $highest = $result->highestSeverity();
        if ($highest !== null && $highest->isAtLeast($failOn)) {
            return 1;
        }

        return 0;
    }

    private function autoFormat(): string
    {
        if (AgentDetector::isAgentRun()) {
            return 'json';
        }

        return 'human';
    }
}

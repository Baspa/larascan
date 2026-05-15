<?php

declare(strict_types=1);

namespace Baspa\Larascan\Commands;

use Baspa\Larascan\Larascan;
use Baspa\Larascan\Reporters\ConsoleReporter;
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
        {--ignore-errors : Force exit 0 even when checks error}';

    protected $description = 'Run larascan security scan';

    public function handle(Larascan $larascan, ConsoleReporter $reporter): int
    {
        $failOnRaw = $this->option('fail-on')
            ?? (string) config('larascan.fail_on', 'high');
        $failOn = Severity::tryFrom((string) $failOnRaw);
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

        $result = $larascan->scan($options);
        $reporter->render($result, $this->output);

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
}

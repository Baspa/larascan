<?php

declare(strict_types=1);

namespace Baspa\Larascan\Commands;

use Baspa\Larascan\Exceptions\BaselineException;
use Baspa\Larascan\Larascan;
use Baspa\Larascan\Reporters\ConsoleReporter;
use Baspa\Larascan\Reporters\JsonReporter;
use Baspa\Larascan\Reporters\SarifReporter;
use Baspa\Larascan\Support\AgentDetector;
use Baspa\Larascan\Support\Baseline;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FindingHasher;
use Baspa\Larascan\Support\ScanOptions;
use Baspa\Larascan\Support\ScanResult;
use Baspa\Larascan\Support\Severity;
use Illuminate\Console\Command;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Output\OutputInterface;

class ScanCommand extends Command
{
    protected $signature = 'larascan
        {--fail-on= : Severity threshold for non-zero exit code (critical|high|medium|low|info)}
        {--check=* : Filter checks by ID pattern (e.g. cookies.*) — repeatable}
        {--category= : Filter checks by category}
        {--ignore-errors : Force exit 0 even when checks error}
        {--only-failed : Hide passed and skipped checks; show only failures and errors}
        {--format= : Output format: human (default), json (auto-selected for agents) or sarif}
        {--output= : Write the report to this file instead of stdout}
        {--baseline= : Path to baseline file (default: larascan-baseline.json)}
        {--no-baseline : Ignore any baseline file}';

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

        try {
            $baseline = $this->resolveBaseline();
        } catch (BaselineException $e) {
            $this->error($e->getMessage());

            return 2;
        }

        $options = new ScanOptions(
            failOn: $failOn,
            checkPatterns: $patterns,
            category: $category,
            baseline: $baseline,
        );

        // Resolve format
        $formatOption = $this->option('format');
        $format = is_string($formatOption) && $formatOption !== ''
            ? strtolower($formatOption)
            : $this->autoFormat();
        if (! in_array($format, ['human', 'json', 'sarif'], true)) {
            $this->error("Invalid --format value: {$format}");

            return 2;
        }

        $outputPath = $this->option('output');
        $outputPath = is_string($outputPath) && $outputPath !== '' ? $outputPath : null;

        $onlyFailed = (bool) $this->option('only-failed');

        $result = $larascan->scan($options);

        if ($outputPath !== null) {
            $buffer = new BufferedOutput;
            $this->renderFormat($format, $result, $buffer, $onlyFailed, $reporter);

            if (@file_put_contents($outputPath, $buffer->fetch()) === false) {
                $this->error("Could not write report to {$outputPath}");

                return 2;
            }

            // Keep CI logs readable: stdout still gets the human report
            // (unless it just went to the file).
            if ($format !== 'human') {
                $reporter->render($result, $this->output, onlyFailed: $onlyFailed);
            }
            $this->line("Report written to {$outputPath}");
        } else {
            $this->renderFormat($format, $result, $this->output, $onlyFailed, $reporter);
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

    /**
     * Resolution order: --baseline flag > config('larascan.baseline') > the
     * implicit default path when the file exists. An explicitly named file
     * that is missing or invalid throws; a missing implicit default is fine.
     *
     * @throws BaselineException
     */
    private function resolveBaseline(): ?Baseline
    {
        if ($this->option('no-baseline')) {
            return null;
        }

        $option = $this->option('baseline');
        $option = is_string($option) && $option !== '' ? $option : null;
        $config = config('larascan.baseline');
        $explicit = $option !== null || (is_string($config) && $config !== '');

        $path = Baseline::resolvePath($option);

        // Only the implicit default may be silently absent; an explicitly
        // named file (flag or config) that is missing throws in fromFile.
        if (! $explicit && ! is_file($path)) {
            return null;
        }

        return Baseline::fromFile($path, new FindingHasher);
    }

    private function renderFormat(string $format, ScanResult $result, OutputInterface $output, bool $onlyFailed, ConsoleReporter $console): void
    {
        match ($format) {
            'json' => (new JsonReporter)->render($result, $output, onlyFailed: $onlyFailed),
            'sarif' => $this->laravel->make(SarifReporter::class)->render($result, $output),
            default => $console->render($result, $output, onlyFailed: $onlyFailed),
        };
    }

    private function autoFormat(): string
    {
        if (AgentDetector::isAgentRun()) {
            return 'json';
        }

        return 'human';
    }
}

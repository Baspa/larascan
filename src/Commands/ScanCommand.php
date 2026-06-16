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

    /**
     * Memory floor (bytes) raised to defensively before a scan when the
     * configured limit is lower. A full scan of a medium app peaks well below
     * this; the headroom turns a would-be OOM into a completed run. See #8.
     */
    private const MEMORY_FLOOR_BYTES = 512 * 1024 * 1024;

    /** Set once the scan and render finish so the shutdown handler stays silent. */
    private bool $scanCompleted = false;

    public function handle(Larascan $larascan, ConsoleReporter $reporter): int
    {
        $this->raiseMemoryFloor();
        $this->registerFatalDiagnostic();

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

        // Past the scan and render: any fatal from here on is not the silent-OOM
        // case the shutdown diagnostic is meant to catch.
        $this->scanCompleted = true;

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
     * Raise the process memory_limit to a safe floor when the configured limit
     * is lower, so a full scan does not silently OOM. Unlimited (`-1`) and any
     * already-higher limit are left untouched.
     */
    private function raiseMemoryFloor(): void
    {
        $target = self::memoryFloorTarget((string) ini_get('memory_limit'));

        if ($target !== null) {
            @ini_set('memory_limit', (string) $target);
        }
    }

    /**
     * The memory_limit (in bytes) to raise to, or null when the current limit is
     * unlimited or already at/above the floor.
     */
    public static function memoryFloorTarget(string $currentLimit): ?int
    {
        $current = self::parseMemoryLimit($currentLimit);

        if ($current !== -1 && $current < self::MEMORY_FLOOR_BYTES) {
            return self::MEMORY_FLOOR_BYTES;
        }

        return null;
    }

    /**
     * Convert a php.ini memory_limit value into bytes. Returns -1 for unlimited.
     */
    public static function parseMemoryLimit(string $value): int
    {
        $value = trim($value);

        if ($value === '' || $value === '-1') {
            return -1;
        }

        $number = (int) $value;
        $unit = strtolower(substr($value, -1));

        return match ($unit) {
            'g' => $number * 1024 * 1024 * 1024,
            'm' => $number * 1024 * 1024,
            'k' => $number * 1024,
            default => $number,
        };
    }

    /**
     * A PHP out-of-memory is a fatal error, not a Throwable, so it escapes the
     * scan's try/catch and the process dies with exit 255 and no output. Register
     * a shutdown handler that turns such a fatal into a clear stderr diagnostic.
     */
    private function registerFatalDiagnostic(): void
    {
        // Hold a little headroom so the handler can still allocate (format and
        // print) after an OOM instead of dying silently a second time; freeing it
        // is the first thing the shutdown closure does.
        $reserve = str_repeat(' ', 256 * 1024);

        register_shutdown_function(function () use (&$reserve): void {
            $reserve = null;
            $this->handleShutdown();
        });
    }

    /**
     * Surface a clear diagnostic if a fatal (e.g. OOM) aborted the scan. Public so
     * it is directly testable; the registered closure frees its reserve first.
     */
    public function handleShutdown(): void
    {
        if ($this->scanCompleted) {
            return;
        }

        $diagnostic = self::fatalDiagnostic(error_get_last());
        if ($diagnostic === null) {
            return;
        }

        $this->renderFatalDiagnostic($diagnostic);
    }

    /**
     * @param  array{headline: string, details: array<int, string>}  $diagnostic
     */
    private function renderFatalDiagnostic(array $diagnostic): void
    {
        $stderr = $this->output->getErrorStyle();
        $stderr->newLine();
        $stderr->error($diagnostic['headline']);
        foreach ($diagnostic['details'] as $line) {
            $stderr->writeln($line);
        }
    }

    /**
     * Build the stderr diagnostic for a fatal that aborted the scan, or null when
     * the last error is not a reportable fatal (so normal runs stay silent).
     *
     * @param  array{type: int, message: string, file: string, line: int}|null  $error
     * @return array{headline: string, details: array<int, string>}|null
     */
    public static function fatalDiagnostic(?array $error): ?array
    {
        if ($error === null || ! in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
            return null;
        }

        if (str_contains($error['message'], 'Allowed memory size')) {
            return [
                'headline' => 'larascan ran out of memory before the scan finished.',
                'details' => [
                    '  '.$error['message'],
                    '  Re-run with a higher limit, e.g. <comment>php -d memory_limit=-1 artisan larascan</comment>',
                ],
            ];
        }

        return [
            'headline' => 'larascan stopped on a fatal error before the scan finished.',
            'details' => ['  '.$error['message']],
        ];
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

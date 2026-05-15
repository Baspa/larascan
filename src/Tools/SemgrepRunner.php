<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tools;

use Baspa\Larascan\Contracts\ToolRunner;
use Baspa\Larascan\Tools\Output\SemgrepMatch;
use JsonException;
use RuntimeException;
use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;

/**
 * Not final by design: subclassing is the supported seam for test doubles.
 */
class SemgrepRunner implements ToolRunner
{
    /**
     * @param  array<int, string>  $configs  paths or registry URLs passed to --config
     * @param  array<int, string>  $targets  paths to scan; defaults to workingDir if empty
     */
    public function __construct(
        private readonly string $workingDir,
        private readonly array $configs = [],
        private readonly array $targets = [],
        private readonly string $binary = 'semgrep',
        private readonly int $timeout = 300,
    ) {}

    public function isAvailable(): bool
    {
        return (new ExecutableFinder)->find($this->binary) !== null;
    }

    /**
     * @return iterable<SemgrepMatch>
     */
    public function run(): iterable
    {
        $command = [$this->binary, '--json', '--quiet'];
        foreach ($this->configs as $config) {
            $command[] = '--config';
            $command[] = $config;
        }
        $command = array_merge($command, $this->targets !== [] ? $this->targets : ['.']);

        $process = new Process($command, $this->workingDir);
        $process->setTimeout((float) $this->timeout);

        // semgrep exits non-zero when findings are present; we parse stdout regardless of exit code.
        $process->run();

        $stdout = $process->getOutput();
        if ($stdout === '') {
            $stderr = trim($process->getErrorOutput());
            throw new RuntimeException(
                $stderr !== ''
                    ? 'semgrep failed: '.$stderr
                    : 'semgrep produced no output',
            );
        }

        yield from $this->parseOutput($stdout);
    }

    /**
     * @return iterable<SemgrepMatch>
     */
    public function parseOutput(string $json): iterable
    {
        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($json, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('Unable to parse semgrep output: '.$e->getMessage(), previous: $e);
        }

        $results = $decoded['results'] ?? [];
        if (! is_array($results)) {
            return;
        }

        foreach ($results as $entry) {
            if (! is_array($entry)) {
                continue;
            }
            $extra = $entry['extra'] ?? [];
            $start = $entry['start'] ?? [];
            $line = is_array($start) && is_int($start['line'] ?? null) ? $start['line'] : 0;

            yield new SemgrepMatch(
                checkId: is_string($entry['check_id'] ?? null) ? $entry['check_id'] : '',
                path: is_string($entry['path'] ?? null) ? $entry['path'] : '',
                line: $line,
                severity: is_array($extra) && is_string($extra['severity'] ?? null) ? $extra['severity'] : 'INFO',
                message: is_array($extra) && is_string($extra['message'] ?? null) ? $extra['message'] : '',
            );
        }
    }
}

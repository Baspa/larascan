<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tools;

use Baspa\Larascan\Contracts\ToolRunner;
use Baspa\Larascan\Tools\Output\NpmAdvisory;
use JsonException;
use RuntimeException;
use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;

/**
 * Not final by design: subclassing is the supported seam for test doubles.
 */
class NpmAuditRunner implements ToolRunner
{
    public function __construct(
        private readonly string $workingDir,
        private readonly string $binary = 'npm',
        private readonly int $timeout = 120,
    ) {}

    public function isAvailable(): bool
    {
        if (! is_file($this->workingDir.'/package.json')) {
            return false;
        }

        return (new ExecutableFinder)->find($this->binary) !== null;
    }

    /**
     * @return iterable<NpmAdvisory>
     */
    public function run(): iterable
    {
        $process = new Process([$this->binary, 'audit', '--json'], $this->workingDir);
        $process->setTimeout((float) $this->timeout);

        // npm audit exits non-zero when vulnerabilities are found; we parse stdout regardless of exit code.
        $process->run();

        $stdout = $process->getOutput();
        if ($stdout === '') {
            $stderr = trim($process->getErrorOutput());
            throw new RuntimeException(
                $stderr !== ''
                    ? 'npm audit failed: '.$stderr
                    : 'npm audit produced no output',
            );
        }

        yield from $this->parseOutput($stdout);
    }

    /**
     * @return iterable<NpmAdvisory>
     */
    public function parseOutput(string $json): iterable
    {
        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($json, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('Unable to parse npm audit output: '.$e->getMessage(), previous: $e);
        }

        $vulns = $decoded['vulnerabilities'] ?? [];
        if (! is_array($vulns)) {
            return;
        }

        foreach ($vulns as $name => $entry) {
            if (! is_array($entry) || ! is_string($name)) {
                continue;
            }

            $title = '';
            $url = null;
            $viaList = $entry['via'] ?? [];
            if (is_array($viaList)) {
                foreach ($viaList as $via) {
                    if (is_array($via) && is_string($via['title'] ?? null)) {
                        $title = $via['title'];
                        $url = is_string($via['url'] ?? null) ? $via['url'] : null;
                        break;
                    }
                }
            }

            yield new NpmAdvisory(
                packageName: $name,
                title: $title !== '' ? $title : "Vulnerability in {$name}",
                severity: is_string($entry['severity'] ?? null) ? $entry['severity'] : 'low',
                range: is_string($entry['range'] ?? null) ? $entry['range'] : null,
                url: $url,
            );
        }
    }
}

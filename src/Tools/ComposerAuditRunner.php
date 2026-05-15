<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tools;

use Baspa\Larascan\Contracts\ToolRunner;
use Baspa\Larascan\Tools\Output\ComposerAdvisory;
use JsonException;
use RuntimeException;
use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;

/**
 * Not final by design: subclassing is the supported seam for test doubles.
 */
class ComposerAuditRunner implements ToolRunner
{
    public function __construct(
        private readonly string $workingDir,
        private readonly string $binary = 'composer',
        private readonly int $timeout = 60,
    ) {}

    public function isAvailable(): bool
    {
        if (! is_file($this->workingDir.'/composer.lock')) {
            return false;
        }

        return (new ExecutableFinder)->find($this->binary) !== null;
    }

    /**
     * @return iterable<ComposerAdvisory>
     */
    public function run(): iterable
    {
        $process = new Process(
            [$this->binary, 'audit', '--format=json', '--locked', '--no-interaction'],
            $this->workingDir,
        );
        $process->setTimeout((float) $this->timeout);

        // composer audit exits non-zero when advisories are found; we parse stdout regardless of exit code.
        $process->run();

        $stdout = $process->getOutput();
        if ($stdout === '') {
            $stderr = trim($process->getErrorOutput());
            throw new RuntimeException(
                $stderr !== ''
                    ? 'composer audit failed: '.$stderr
                    : 'composer audit produced no output',
            );
        }

        yield from $this->parseOutput($stdout);
    }

    /**
     * @return iterable<ComposerAdvisory>
     */
    public function parseOutput(string $json): iterable
    {
        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($json, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('Unable to parse composer audit output: '.$e->getMessage(), previous: $e);
        }

        $advisoriesRaw = $decoded['advisories'] ?? [];
        if (! is_array($advisoriesRaw)) {
            return;
        }

        foreach ($advisoriesRaw as $perPackage) {
            if (! is_array($perPackage)) {
                continue;
            }
            foreach ($perPackage as $entry) {
                if (! is_array($entry)) {
                    continue;
                }
                yield new ComposerAdvisory(
                    packageName: is_string($entry['packageName'] ?? null) ? $entry['packageName'] : '',
                    title: is_string($entry['title'] ?? null) ? $entry['title'] : '',
                    severity: is_string($entry['severity'] ?? null) ? $entry['severity'] : 'medium',
                    cve: is_string($entry['cve'] ?? null) ? $entry['cve'] : null,
                    link: is_string($entry['link'] ?? null) ? $entry['link'] : null,
                    affectedVersions: is_string($entry['affectedVersions'] ?? null) ? $entry['affectedVersions'] : null,
                );
            }
        }
    }
}

<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tools;

use Baspa\Larascan\Contracts\ToolRunner;
use Baspa\Larascan\Tools\Output\PhpStanIssue;
use JsonException;
use RuntimeException;
use Symfony\Component\Process\Process;

/**
 * Not final by design: subclassing is the supported seam for test doubles.
 */
class PhpStanRunner implements ToolRunner
{
    /**
     * @param  array<int, string>  $paths
     */
    public function __construct(
        private readonly string $workingDir,
        private readonly ?string $configFile = null,
        private readonly array $paths = [],
        private readonly int $timeout = 300,
    ) {}

    public function isAvailable(): bool
    {
        return is_file($this->workingDir.'/vendor/bin/phpstan');
    }

    /**
     * @return iterable<PhpStanIssue>
     */
    public function run(): iterable
    {
        $binary = $this->workingDir.'/vendor/bin/phpstan';
        $command = [$binary, 'analyse', '--error-format=json', '--no-progress'];
        if ($this->configFile !== null) {
            $command[] = '--configuration';
            $command[] = $this->configFile;
        }
        $command = array_merge($command, $this->paths);

        $process = new Process($command, $this->workingDir);
        $process->setTimeout((float) $this->timeout);

        // phpstan exits non-zero when issues are found; we parse stdout regardless of exit code.
        $process->run();

        $stdout = $process->getOutput();
        if ($stdout === '') {
            $stderr = trim($process->getErrorOutput());
            throw new RuntimeException(
                $stderr !== ''
                    ? 'phpstan failed: '.$stderr
                    : 'phpstan produced no output',
            );
        }

        yield from $this->parseOutput($stdout);
    }

    /**
     * @return iterable<PhpStanIssue>
     */
    public function parseOutput(string $json): iterable
    {
        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($json, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('Unable to parse phpstan output: '.$e->getMessage(), previous: $e);
        }

        $files = $decoded['files'] ?? [];
        if (! is_array($files)) {
            return;
        }

        foreach ($files as $path => $fileEntry) {
            if (! is_array($fileEntry) || ! is_string($path)) {
                continue;
            }
            $messages = $fileEntry['messages'] ?? [];
            if (! is_array($messages)) {
                continue;
            }
            foreach ($messages as $msg) {
                if (! is_array($msg)) {
                    continue;
                }
                yield new PhpStanIssue(
                    file: $path,
                    line: is_int($msg['line'] ?? null) ? $msg['line'] : 0,
                    message: is_string($msg['message'] ?? null) ? $msg['message'] : '',
                    identifier: is_string($msg['identifier'] ?? null) ? $msg['identifier'] : null,
                    ignorable: (bool) ($msg['ignorable'] ?? false),
                );
            }
        }
    }
}

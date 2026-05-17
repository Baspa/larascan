<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tools;

use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;
use Throwable;

class ComposerOutdatedRunner
{
    public function __construct(
        private readonly string $workingDir,
        private readonly string $binary,
    ) {}

    public function isAvailable(): bool
    {
        if (! is_file($this->workingDir.'/composer.json')) {
            return false;
        }

        return (new ExecutableFinder)->find($this->binary) !== null;
    }

    /**
     * @return array<int, array{name: string, current: string, latest: string, status: string}>
     */
    public function run(): array
    {
        try {
            $process = new Process(
                [$this->binary, 'outdated', '--direct', '--format=json', '--no-interaction', '--no-ansi'],
                $this->workingDir,
            );
            $process->setTimeout(60);
            $process->run();

            return self::parse($process->getOutput());
        } catch (Throwable) {
            return [];
        }
    }

    /**
     * @return array<int, array{name: string, current: string, latest: string, status: string}>
     */
    public static function parse(string $json): array
    {
        if ($json === '') {
            return [];
        }

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            return [];
        }

        if (! is_array($decoded) || ! isset($decoded['installed']) || ! is_array($decoded['installed'])) {
            return [];
        }

        $out = [];
        foreach ($decoded['installed'] as $entry) {
            if (! is_array($entry)) {
                continue;
            }
            $name = is_string($entry['name'] ?? null) ? $entry['name'] : null;
            $current = is_string($entry['version'] ?? null) ? $entry['version'] : null;
            $latest = is_string($entry['latest'] ?? null) ? $entry['latest'] : null;
            $status = is_string($entry['latest-status'] ?? null) ? $entry['latest-status'] : 'unknown';

            if ($name === null || $current === null || $latest === null) {
                continue;
            }

            $out[] = ['name' => $name, 'current' => $current, 'latest' => $latest, 'status' => $status];
        }

        return $out;
    }
}

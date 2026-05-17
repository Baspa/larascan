<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tools;

use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;
use Throwable;

class NpmOutdatedRunner
{
    public function __construct(
        private readonly string $workingDir,
        private readonly string $binary,
    ) {}

    public function isAvailable(): bool
    {
        if (! is_file($this->workingDir.'/package.json')) {
            return false;
        }

        return (new ExecutableFinder)->find($this->binary) !== null;
    }

    /**
     * @return array<int, array{name: string, current: string, latest: string}>
     */
    public function run(): array
    {
        try {
            $process = new Process([$this->binary, 'outdated', '--depth=0', '--json'], $this->workingDir);
            $process->setTimeout(60);
            $process->run();

            return self::parse($process->getOutput());
        } catch (Throwable) {
            return [];
        }
    }

    /**
     * @return array<int, array{name: string, current: string, latest: string}>
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

        if (! is_array($decoded)) {
            return [];
        }

        $out = [];
        foreach ($decoded as $name => $entry) {
            if (! is_string($name) || ! is_array($entry)) {
                continue;
            }
            $current = is_string($entry['current'] ?? null) ? $entry['current'] : null;
            $latest = is_string($entry['latest'] ?? null) ? $entry['latest'] : null;
            if ($current === null || $latest === null) {
                continue;
            }
            $out[] = ['name' => $name, 'current' => $current, 'latest' => $latest];
        }

        return $out;
    }
}

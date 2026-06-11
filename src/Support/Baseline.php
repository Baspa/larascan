<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

use Baspa\Larascan\Exceptions\BaselineException;

final readonly class Baseline
{
    public const VERSION = 1;

    /**
     * @param  array<string, array{check: string, file: ?string, message: string, severity: string, count: int}>  $entries  keyed by finding hash
     */
    private function __construct(
        private array $entries,
        private FindingHasher $hasher,
    ) {}

    public static function fromFile(string $path, FindingHasher $hasher): self
    {
        if (! is_file($path)) {
            throw new BaselineException("Baseline file not found: {$path}");
        }

        $raw = file_get_contents($path);
        if ($raw === false) {
            throw new BaselineException("Baseline file could not be read: {$path}");
        }

        $decoded = json_decode($raw, true);
        if (! is_array($decoded)) {
            throw new BaselineException("Baseline file contains invalid JSON: {$path}");
        }

        $version = $decoded['version'] ?? null;
        if ($version !== self::VERSION) {
            throw new BaselineException(sprintf(
                'Unsupported baseline version %s in %s (expected %d) — re-run php artisan larascan:baseline',
                json_encode($version),
                $path,
                self::VERSION,
            ));
        }

        $findings = $decoded['findings'] ?? null;
        if (! is_array($findings)) {
            throw new BaselineException("Baseline file is missing its findings array: {$path}");
        }

        $entries = [];
        foreach ($findings as $entry) {
            if (! is_array($entry)) {
                throw new BaselineException("Baseline file contains a malformed finding entry: {$path}");
            }

            $check = $entry['check'] ?? null;
            $file = $entry['file'] ?? null;
            $message = $entry['message'] ?? null;
            $severity = $entry['severity'] ?? null;
            $count = $entry['count'] ?? 1;

            if (! is_string($check) || ! is_string($message)
                || ($file !== null && ! is_string($file))
                || ! is_string($severity)
                || ! is_int($count) || $count < 1
            ) {
                throw new BaselineException("Baseline file contains a malformed finding entry: {$path}");
            }

            $hash = $hasher->hashRaw($check, $file, $message);

            if (isset($entries[$hash])) {
                $entries[$hash]['count'] += $count;
            } else {
                $entries[$hash] = [
                    'check' => $check,
                    'file' => $file,
                    'message' => $message,
                    'severity' => $severity,
                    'count' => $count,
                ];
            }
        }

        return new self($entries, $hasher);
    }

    /**
     * @param  array<int, Finding>  $findings
     */
    public static function fromFindings(array $findings, FindingHasher $hasher): self
    {
        $entries = [];
        foreach ($findings as $finding) {
            $hash = $hasher->hash($finding);

            if (isset($entries[$hash])) {
                $entries[$hash]['count']++;
            } else {
                $entries[$hash] = [
                    'check' => $finding->checkId,
                    'file' => $finding->file,
                    'message' => $finding->message,
                    'severity' => $finding->severity->value,
                    'count' => 1,
                ];
            }
        }

        return new self($entries, $hasher);
    }

    /**
     * Resolve the baseline path: explicit option > config('larascan.baseline')
     * > the default file in the project root.
     */
    public static function resolvePath(?string $option): string
    {
        $config = config('larascan.baseline');

        return match (true) {
            $option !== null && $option !== '' => $option,
            is_string($config) && $config !== '' => $config,
            default => base_path('larascan-baseline.json'),
        };
    }

    public function toJson(): string
    {
        $findings = array_values($this->entries);
        usort(
            $findings,
            fn (array $a, array $b): int => [$a['check'], $a['file'] ?? '', $a['message']]
                <=> [$b['check'], $b['file'] ?? '', $b['message']],
        );

        return (string) json_encode([
            'version' => self::VERSION,
            'generated_at' => date(DATE_ATOM),
            'findings' => $findings,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    }

    /**
     * Total number of baselined finding occurrences.
     */
    public function count(): int
    {
        $total = 0;
        foreach ($this->entries as $entry) {
            $total += $entry['count'];
        }

        return $total;
    }

    public function matcher(): BaselineMatcher
    {
        $remaining = [];
        foreach ($this->entries as $hash => $entry) {
            $remaining[$hash] = $entry['count'];
        }

        return new BaselineMatcher($remaining, $this->hasher);
    }
}

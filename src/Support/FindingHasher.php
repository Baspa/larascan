<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

final class FindingHasher
{
    public function hash(Finding $finding): string
    {
        return $this->hashRaw($finding->checkId, $finding->file, $finding->message);
    }

    public function hashRaw(string $checkId, ?string $file, string $message): string
    {
        // Checks build paths with DIRECTORY_SEPARATOR; normalize separators so
        // a baseline written on Windows still matches on Linux CI.
        $file = str_replace('\\', '/', $file ?? '');

        return hash('sha256', $checkId.'|'.$file.'|'.$this->normalize($message));
    }

    /**
     * Normalize a finding message so volatile details (line numbers embedded
     * as `:123`, whitespace differences) don't invalidate baseline entries.
     */
    private function normalize(string $message): string
    {
        $normalized = (string) preg_replace('/:\d+/', ':L', $message);
        $normalized = (string) preg_replace('/\s+/', ' ', $normalized);

        return trim($normalized);
    }
}

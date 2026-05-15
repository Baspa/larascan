<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tools\Output;

final readonly class SemgrepMatch
{
    public function __construct(
        public string $checkId,
        public string $path,
        public int $line,
        public string $severity,
        public string $message,
    ) {}
}

<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

final readonly class Finding
{
    public function __construct(
        public string $checkId,
        public Severity $severity,
        public string $message,
        public ?string $file = null,
        public ?int $line = null,
        public ?string $snippet = null,
    ) {}
}

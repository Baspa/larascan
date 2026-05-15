<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tools\Output;

final readonly class PhpStanIssue
{
    public function __construct(
        public string $file,
        public int $line,
        public string $message,
        public ?string $identifier = null,
        public bool $ignorable = false,
    ) {}
}

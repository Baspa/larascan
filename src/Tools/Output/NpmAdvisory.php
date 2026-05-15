<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tools\Output;

final readonly class NpmAdvisory
{
    public function __construct(
        public string $packageName,
        public string $title,
        public string $severity,
        public ?string $range = null,
        public ?string $url = null,
    ) {}
}

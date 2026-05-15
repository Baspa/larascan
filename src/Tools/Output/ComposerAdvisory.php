<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tools\Output;

final readonly class ComposerAdvisory
{
    public function __construct(
        public string $packageName,
        public string $title,
        public string $severity,
        public ?string $cve = null,
        public ?string $link = null,
        public ?string $affectedVersions = null,
    ) {}
}

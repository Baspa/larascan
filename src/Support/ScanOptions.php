<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

final readonly class ScanOptions
{
    /**
     * @param  array<int, string>  $checkPatterns  e.g. ['cookies.*']
     */
    public function __construct(
        public Severity $failOn = Severity::High,
        public array $checkPatterns = [],
        public ?Category $category = null,
    ) {}
}

<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

final readonly class AdviceOutcome
{
    /**
     * @param  array<int, AdviceEvidence>  $evidence
     */
    public function __construct(
        public AdviceStatus $status,
        public string $summary = '',
        public array $evidence = [],
        public ?string $skipReason = null,
    ) {}

    /**
     * @param  array<int, AdviceEvidence>  $evidence
     */
    public static function surfaced(string $summary, array $evidence = []): self
    {
        return new self(AdviceStatus::Surfaced, $summary, $evidence);
    }

    public static function notSurfaced(): self
    {
        return new self(AdviceStatus::NotSurfaced);
    }

    public static function skipped(string $reason): self
    {
        return new self(AdviceStatus::Skipped, skipReason: $reason);
    }

    public static function errored(string $message): self
    {
        return new self(AdviceStatus::Errored, summary: $message);
    }
}

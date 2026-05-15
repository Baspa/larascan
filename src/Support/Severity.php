<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

enum Severity: string
{
    case Critical = 'critical';
    case High = 'high';
    case Medium = 'medium';
    case Low = 'low';
    case Info = 'info';

    public function rank(): int
    {
        return match ($this) {
            self::Critical => 5,
            self::High => 4,
            self::Medium => 3,
            self::Low => 2,
            self::Info => 1,
        };
    }

    public function isAtLeast(self $other): bool
    {
        return $this->rank() >= $other->rank();
    }

    public static function fromCvssScore(float $score): self
    {
        return match (true) {
            $score >= 9.0 => self::Critical,
            $score >= 7.0 => self::High,
            $score >= 4.0 => self::Medium,
            $score >= 0.1 => self::Low,
            default => self::Info,
        };
    }

    public function downgradeIfNotProduction(string $envValue): self
    {
        return $envValue === 'production' ? $this : self::Info;
    }
}

<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

use Throwable;

final class ScanResult
{
    /**
     * @param  array<string, CheckStatus>  $statuses
     * @param  array<int, Finding>  $findings
     * @param  array<string, string>  $skipReasons
     * @param  array<string, string>  $errors
     * @param  array<int, Finding>  $baselinedFindings
     */
    public function __construct(
        private array $statuses = [],
        private array $findings = [],
        private array $skipReasons = [],
        private array $errors = [],
        private array $baselinedFindings = [],
        private int $staleBaselineCount = 0,
    ) {}

    /**
     * @param  iterable<Finding>  $findings
     * @param  iterable<Finding>  $baselinedFindings
     */
    public function record(string $checkId, CheckStatus $status, iterable $findings, ?string $skipReason = null, iterable $baselinedFindings = []): self
    {
        $statuses = $this->statuses;
        $statuses[$checkId] = $status;

        $allFindings = $this->findings;
        foreach ($findings as $f) {
            $allFindings[] = $f;
        }

        $allBaselined = $this->baselinedFindings;
        foreach ($baselinedFindings as $f) {
            $allBaselined[] = $f;
        }

        $skipReasons = $this->skipReasons;
        if ($skipReason !== null) {
            $skipReasons[$checkId] = $skipReason;
        }

        return new self($statuses, $allFindings, $skipReasons, $this->errors, $allBaselined, $this->staleBaselineCount);
    }

    public function recordError(string $checkId, Throwable $e): self
    {
        $statuses = $this->statuses;
        $statuses[$checkId] = CheckStatus::Errored;

        $errors = $this->errors;
        $errors[$checkId] = $e::class.': '.$e->getMessage();

        return new self($statuses, $this->findings, $this->skipReasons, $errors, $this->baselinedFindings, $this->staleBaselineCount);
    }

    public function statusOf(string $checkId): ?CheckStatus
    {
        return $this->statuses[$checkId] ?? null;
    }

    public function skipReasonOf(string $checkId): ?string
    {
        return $this->skipReasons[$checkId] ?? null;
    }

    public function errorOf(string $checkId): ?string
    {
        return $this->errors[$checkId] ?? null;
    }

    /**
     * @return array<int, Finding>
     */
    public function findings(): array
    {
        return $this->findings;
    }

    /**
     * @return array<string, int>
     */
    public function counts(): array
    {
        $counts = ['passed' => 0, 'failed' => 0, 'skipped' => 0, 'errored' => 0];
        foreach ($this->statuses as $status) {
            $counts[$status->value]++;
        }

        return $counts;
    }

    public function highestSeverity(): ?Severity
    {
        $highest = null;
        foreach ($this->findings as $f) {
            if ($highest === null || $f->severity->isAtLeast($highest)) {
                $highest = $f->severity;
            }
        }

        return $highest;
    }

    /**
     * @return array<string, CheckStatus>
     */
    public function statuses(): array
    {
        return $this->statuses;
    }

    /**
     * @return array<int, Finding>
     */
    public function baselinedFindings(): array
    {
        return $this->baselinedFindings;
    }

    public function baselinedCount(): int
    {
        return count($this->baselinedFindings);
    }

    public function baselinedCountOf(string $checkId): int
    {
        $count = 0;
        foreach ($this->baselinedFindings as $f) {
            if ($f->checkId === $checkId) {
                $count++;
            }
        }

        return $count;
    }

    public function withStaleBaselineCount(int $staleBaselineCount): self
    {
        return new self(
            $this->statuses,
            $this->findings,
            $this->skipReasons,
            $this->errors,
            $this->baselinedFindings,
            $staleBaselineCount,
        );
    }

    public function staleBaselineCount(): int
    {
        return $this->staleBaselineCount;
    }
}

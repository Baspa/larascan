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
     */
    public function __construct(
        private array $statuses = [],
        private array $findings = [],
        private array $skipReasons = [],
        private array $errors = [],
    ) {}

    /**
     * @param  iterable<Finding>  $findings
     */
    public function record(string $checkId, CheckStatus $status, iterable $findings, ?string $skipReason = null): self
    {
        $statuses = $this->statuses;
        $statuses[$checkId] = $status;

        $allFindings = $this->findings;
        foreach ($findings as $f) {
            $allFindings[] = $f;
        }

        $skipReasons = $this->skipReasons;
        if ($skipReason !== null) {
            $skipReasons[$checkId] = $skipReason;
        }

        return new self($statuses, $allFindings, $skipReasons, $this->errors);
    }

    public function recordError(string $checkId, Throwable $e): self
    {
        $statuses = $this->statuses;
        $statuses[$checkId] = CheckStatus::Errored;

        $errors = $this->errors;
        $errors[$checkId] = $e::class.': '.$e->getMessage();

        return new self($statuses, $this->findings, $this->skipReasons, $errors);
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
}

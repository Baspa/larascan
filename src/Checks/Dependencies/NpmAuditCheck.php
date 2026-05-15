<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Dependencies;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Baspa\Larascan\Tools\NpmAuditRunner;

final class NpmAuditCheck extends AbstractCheck
{
    public function __construct(
        private readonly NpmAuditRunner $runner,
    ) {}

    public function id(): string
    {
        return 'dependencies.npm-audit';
    }

    public function category(): Category
    {
        return Category::Dependencies;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'npm audit — vulnerable JS dependencies';
    }

    public function isApplicable(): bool
    {
        return $this->runner->isAvailable();
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        foreach ($this->runner->run() as $advisory) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severityFromString($advisory->severity),
                message: sprintf(
                    '%s%s — %s',
                    $advisory->packageName,
                    $advisory->range !== null ? " {$advisory->range}" : '',
                    $advisory->title,
                ),
            );
        }
    }

    private function severityFromString(string $value): Severity
    {
        return match (strtolower($value)) {
            'critical' => Severity::Critical,
            'high' => Severity::High,
            'moderate', 'medium' => Severity::Medium,
            'low' => Severity::Low,
            default => Severity::Info,
        };
    }
}

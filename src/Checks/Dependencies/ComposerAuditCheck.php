<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Dependencies;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Baspa\Larascan\Tools\ComposerAuditRunner;

final class ComposerAuditCheck extends AbstractCheck
{
    public function __construct(
        private readonly ComposerAuditRunner $runner,
    ) {}

    public function id(): string
    {
        return 'dependencies.composer-audit';
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
        return 'composer audit — vulnerable dependencies';
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
                    '%s — %s%s',
                    $advisory->packageName,
                    $advisory->title,
                    $advisory->cve !== null ? " ({$advisory->cve})" : '',
                ),
            );
        }
    }

    private function severityFromString(string $value): Severity
    {
        return match (strtolower($value)) {
            'critical' => Severity::Critical,
            'high' => Severity::High,
            'medium', 'moderate' => Severity::Medium,
            'low' => Severity::Low,
            default => Severity::Info,
        };
    }
}

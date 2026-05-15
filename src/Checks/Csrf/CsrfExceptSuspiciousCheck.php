<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Csrf;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Foundation\Application;
use ReflectionClass;
use Throwable;

final class CsrfExceptSuspiciousCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'csrf.except-suspicious';
    }

    public function category(): Category
    {
        return Category::Csrf;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'CSRF except list should not contain broad wildcards';
    }

    public function isApplicable(): bool
    {
        return class_exists('Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken');
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        try {
            $middleware = $this->app->make('Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken');
        } catch (Throwable) {
            return;
        }

        try {
            $reflection = new ReflectionClass($middleware);
            if (! $reflection->hasProperty('except')) {
                return;
            }
            $value = $reflection->getProperty('except')->getValue($middleware);
        } catch (Throwable) {
            return;
        }

        if (! is_array($value)) {
            return;
        }

        foreach ($value as $entry) {
            if (! is_string($entry)) {
                continue;
            }

            if (! $this->isSuspicious($entry)) {
                continue;
            }

            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: "CSRF except list contains suspicious pattern '{$entry}' — this disables CSRF protection for entire URL trees.",
            );
        }
    }

    private function isSuspicious(string $entry): bool
    {
        // Any entry containing `*` is flagged: it disables CSRF for an entire
        // URL tree rather than a single, well-defined endpoint. A specific
        // path like `/webhook/stripe` is fine.
        return str_contains($entry, '*');
    }
}

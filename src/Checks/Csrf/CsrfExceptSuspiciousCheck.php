<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Csrf;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\MiddlewareIntrospection;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
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
        return class_exists(PreventRequestForgery::class);
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        foreach ($this->excludedPaths() as $entry) {
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

    /**
     * @return array<int, string>
     */
    private function excludedPaths(): array
    {
        // Middleware attached per route never shows up in the kernel, and the
        // bootstrap/app.php list is global, so fall back to the framework class.
        $classes = MiddlewareIntrospection::registeredSubclassesOf($this->app, PreventRequestForgery::class)
            ?: [PreventRequestForgery::class];

        $paths = [];
        foreach ($classes as $class) {
            try {
                $paths = [...$paths, ...$this->app->make($class)->getExcludedPaths()];
            } catch (Throwable) {
                continue;
            }
        }

        return array_values(array_unique(array_filter($paths, is_string(...))));
    }

    private function isSuspicious(string $entry): bool
    {
        // Any entry containing `*` is flagged: it disables CSRF for an entire
        // URL tree rather than a single, well-defined endpoint. A specific
        // path like `/webhook/stripe` is fine.
        return str_contains($entry, '*');
    }
}

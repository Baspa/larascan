<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Headers;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\MiddlewareIntrospection;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class CspDefinedCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'headers.csp-defined';
    }

    public function category(): Category
    {
        return Category::Headers;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'Content-Security-Policy middleware must be active';
    }

    public function isApplicable(): bool
    {
        return class_exists('Spatie\\Csp\\AddCspHeaders');
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        if (MiddlewareIntrospection::anyMatching($this->app, ['AddCspHeaders', 'ContentSecurityPolicy', 'SecureHeaders'])) {
            return;
        }

        /** @var Repository $config */
        $config = $this->app->make('config');
        $env = (string) ($config->get('app.env') ?? '');

        yield new Finding(
            checkId: $this->id(),
            severity: $this->severity()->downgradeIfNotProduction($env),
            message: 'spatie/laravel-csp is installed but no CSP middleware is registered in the kernel. Add Spatie\\Csp\\AddCspHeaders to the web middleware group.',
        );
    }
}

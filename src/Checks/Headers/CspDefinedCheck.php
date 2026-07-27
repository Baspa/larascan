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

        // Apps routinely subclass AddCspHeaders to skip the policy on routes they
        // don't control (Horizon, Pulse and friends rely on inline scripts). The
        // subclass is registered instead of the parent and its name need not
        // contain "AddCspHeaders", so name matching alone reports a policy that
        // is in fact active.
        if (MiddlewareIntrospection::anySubclassOf($this->app, 'Spatie\\Csp\\AddCspHeaders')) {
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

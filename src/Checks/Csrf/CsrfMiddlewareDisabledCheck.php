<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Csrf;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\MiddlewareIntrospection;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Foundation\Application;

final class CsrfMiddlewareDisabledCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'csrf.middleware-disabled';
    }

    public function category(): Category
    {
        return Category::Csrf;
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function name(): string
    {
        return 'CSRF protection middleware must be registered';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        // The CSRF middleware has been renamed across Laravel versions, so match
        // every name it has shipped under. Both deprecated aliases extend the
        // current class:
        //   - VerifyCsrfToken       (Laravel <= 10, and as a deprecated alias)
        //   - ValidateCsrfToken     (Laravel 11 / 12, deprecated alias since 13)
        //   - PreventRequestForgery (Laravel 13+, registered in the default web group)
        if (MiddlewareIntrospection::anyMatching($this->app, [
            'VerifyCsrfToken',
            'ValidateCsrfToken',
            'PreventRequestForgery',
        ])) {
            return;
        }

        yield new Finding(
            checkId: $this->id(),
            severity: $this->severity(),
            message: 'CSRF protection middleware (PreventRequestForgery / ValidateCsrfToken / VerifyCsrfToken) is not registered — POST/PUT/PATCH/DELETE routes accept requests without CSRF tokens, enabling cross-site request forgery.',
        );
    }
}

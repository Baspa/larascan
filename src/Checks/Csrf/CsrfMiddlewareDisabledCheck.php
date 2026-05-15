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
        return 'VerifyCsrfToken middleware must be registered';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        if (MiddlewareIntrospection::anyMatching($this->app, ['VerifyCsrfToken'])) {
            return;
        }

        yield new Finding(
            checkId: $this->id(),
            severity: $this->severity(),
            message: 'VerifyCsrfToken middleware is not registered — POST/PUT/PATCH/DELETE routes accept requests without CSRF tokens, enabling cross-site request forgery.',
        );
    }
}

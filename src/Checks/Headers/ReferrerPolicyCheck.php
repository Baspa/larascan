<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Headers;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\MiddlewareIntrospection;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Foundation\Application;

final class ReferrerPolicyCheck extends AbstractCheck
{
    private const KEYWORDS = ['ReferrerPolicy', 'SecureHeaders'];

    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'headers.referrer-policy';
    }

    public function category(): Category
    {
        return Category::Headers;
    }

    public function severity(): Severity
    {
        return Severity::Low;
    }

    public function name(): string
    {
        return 'Referrer-Policy header middleware should be active';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        if (MiddlewareIntrospection::anyMatching($this->app, self::KEYWORDS)) {
            return;
        }

        yield new Finding(
            checkId: $this->id(),
            severity: $this->severity(),
            message: 'No Referrer-Policy middleware detected — set a Referrer-Policy header to control referrer information leakage.',
        );
    }
}

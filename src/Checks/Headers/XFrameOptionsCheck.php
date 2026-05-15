<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Headers;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\MiddlewareIntrospection;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Foundation\Application;

final class XFrameOptionsCheck extends AbstractCheck
{
    private const KEYWORDS = ['XFrame', 'FrameOptions', 'SecureHeaders'];

    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'headers.x-frame-options';
    }

    public function category(): Category
    {
        return Category::Headers;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'X-Frame-Options or frame-ancestors must be set to prevent clickjacking';
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
            message: 'No X-Frame-Options middleware detected — without it, your application may be vulnerable to clickjacking attacks.',
        );
    }
}

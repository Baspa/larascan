<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Headers;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\MiddlewareIntrospection;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Foundation\Application;

final class XContentTypeOptionsCheck extends AbstractCheck
{
    private const KEYWORDS = ['XContentType', 'NoSniff', 'SecureHeaders'];

    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'headers.x-content-type-options';
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
        return 'X-Content-Type-Options: nosniff middleware must be active';
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
            message: 'No X-Content-Type-Options middleware detected — without nosniff, browsers may MIME-sniff responses and execute untrusted content.',
        );
    }
}

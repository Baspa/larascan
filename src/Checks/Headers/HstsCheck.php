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

final class HstsCheck extends AbstractCheck
{
    private const KEYWORDS = ['Hsts', 'StrictTransportSecurity', 'SecureHeaders'];

    private const HEADER = 'Strict-Transport-Security';

    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'headers.hsts';
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
        return 'HSTS header middleware must be active in production';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        if (MiddlewareIntrospection::anyMatching($this->app, self::KEYWORDS)) {
            return;
        }

        // No package owns this header, so the middleware can be called anything —
        // "SecurityHeaders" is a common choice and matches none of the keywords
        // above. Fall back to reading the registered middleware for the header
        // name itself, which is what actually decides whether it gets sent.
        if (MiddlewareIntrospection::anyMentioningInSource($this->app, self::HEADER)) {
            return;
        }

        /** @var Repository $config */
        $config = $this->app->make('config');
        $env = (string) ($config->get('app.env') ?? '');

        yield new Finding(
            checkId: $this->id(),
            severity: $this->severity()->downgradeIfNotProduction($env),
            message: 'No HSTS middleware detected in the HTTP kernel — Strict-Transport-Security header is essential for HTTPS-only deployments.',
        );
    }
}

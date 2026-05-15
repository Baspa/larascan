<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Cookies;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class SessionSameSiteCheck extends AbstractCheck
{
    private const ACCEPTABLE = ['lax', 'strict'];

    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'cookies.session-same-site';
    }

    public function category(): Category
    {
        return Category::Cookies;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'session.same_site must be lax or strict';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        /** @var Repository $config */
        $config = $this->app->make('config');

        $value = $config->get('session.same_site');
        if (is_string($value) && in_array(strtolower($value), self::ACCEPTABLE, true)) {
            return;
        }

        yield new Finding(
            checkId: $this->id(),
            severity: $this->severity(),
            message: 'session.same_site must be "lax" or "strict" — "none" or unset leaves the app vulnerable to CSRF via cross-site cookie attachment.',
        );
    }
}

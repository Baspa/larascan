<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Cookies;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class SessionSecureCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'cookies.session-secure';
    }

    public function category(): Category
    {
        return Category::Cookies;
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function name(): string
    {
        return 'SESSION_SECURE_COOKIE must be true in production';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        /** @var Repository $config */
        $config = $this->app->make('config');

        if (filter_var($config->get('session.secure'), FILTER_VALIDATE_BOOLEAN)) {
            return;
        }

        $env = (string) ($config->get('app.env') ?? '');

        yield new Finding(
            checkId: $this->id(),
            severity: $this->severity()->downgradeIfNotProduction($env),
            message: 'SESSION_SECURE_COOKIE is false — sessions cookies will be sent over HTTP and can be hijacked on shared networks.',
        );
    }
}

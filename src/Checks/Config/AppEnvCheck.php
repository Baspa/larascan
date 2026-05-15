<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Config;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class AppEnvCheck extends AbstractCheck
{
    private const DEV_ENVS = ['local', 'testing', 'dev', 'development'];

    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'config.app-env';
    }

    public function category(): Category
    {
        return Category::Config;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'APP_ENV must not be a development value in production';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        /** @var Repository $config */
        $config = $this->app->make('config');
        $env = $config->get('app.env');

        if (! is_string($env) || ! in_array(strtolower($env), self::DEV_ENVS, true)) {
            return;
        }

        yield new Finding(
            checkId: $this->id(),
            severity: $this->severity()->downgradeIfNotProduction((string) $env),
            message: "APP_ENV is '{$env}' — leaks development-mode behavior in production.",
        );
    }
}

<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Config;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class AppDebugCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'config.app-debug';
    }

    public function category(): Category
    {
        return Category::Config;
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function name(): string
    {
        return 'APP_DEBUG must be false in production';
    }

    public function isApplicable(): bool
    {
        /** @var Repository $config */
        $config = $this->app->make('config');

        return $config->get('app.env') === 'production';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        /** @var Repository $config */
        $config = $this->app->make('config');

        if (filter_var($config->get('app.debug'), FILTER_VALIDATE_BOOLEAN)) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: 'APP_DEBUG is true in production — leaks stack traces and config to attackers.',
            );
        }
    }
}

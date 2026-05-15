<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Config;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class AppKeyCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'config.app-key';
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
        return 'APP_KEY must be set and non-empty';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        /** @var Repository $config */
        $config = $this->app->make('config');
        $key = $config->get('app.key');

        if (! is_string($key) || $key === '') {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: 'APP_KEY is empty or missing — sessions, cookies, and encrypted values cannot be secured.',
            );
        }
    }
}

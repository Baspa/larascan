<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Config;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class LogLevelCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'config.log-level';
    }

    public function category(): Category
    {
        return Category::Config;
    }

    public function severity(): Severity
    {
        return Severity::Low;
    }

    public function name(): string
    {
        return 'Default log channel must not be at debug level in production';
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

        $default = $config->get('logging.default');
        if (! is_string($default)) {
            return;
        }

        $level = $config->get("logging.channels.{$default}.level");
        if (is_string($level) && strtolower($level) === 'debug') {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: "Default log channel '{$default}' is at debug level in production — risks leaking sensitive data via logs.",
            );
        }
    }
}

<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Ecosystem;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class DebugbarEnabledCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'ecosystem.debugbar-enabled';
    }

    public function category(): Category
    {
        return Category::Ecosystem;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'Debugbar must not be enabled at runtime in production';
    }

    public function isApplicable(): bool
    {
        return class_exists('Barryvdh\\Debugbar\\LaravelDebugbar');
    }

    /**
     * Composer placement (require vs require-dev) is covered by
     * repo.debug-toolbars; this check covers runtime configuration.
     *
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        /** @var Repository $config */
        $config = $this->app->make('config');

        if ($config->get('app.env') !== 'production') {
            return;
        }

        $enabled = $config->get('debugbar.enabled');

        if ($enabled !== null && filter_var($enabled, FILTER_VALIDATE_BOOLEAN)) {
            yield new Finding(
                checkId: $this->id(),
                severity: Severity::Critical,
                message: 'debugbar.enabled is explicitly true in production — Debugbar exposes queries, session data, and request internals to visitors. Set DEBUGBAR_ENABLED=false. (Composer placement is covered by repo.debug-toolbars.)',
            );

            return;
        }

        if ($enabled === null && filter_var($config->get('app.debug'), FILTER_VALIDATE_BOOLEAN)) {
            yield new Finding(
                checkId: $this->id(),
                severity: Severity::High,
                message: 'debugbar.enabled is null and app.debug is true — Debugbar follows app.debug when unset, so it is active in production. Set DEBUGBAR_ENABLED=false or fix APP_DEBUG. (Composer placement is covered by repo.debug-toolbars.)',
            );
        }
    }
}

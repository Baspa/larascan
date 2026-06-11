<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Ecosystem;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class TelescopeProductionCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'ecosystem.telescope-production';
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
        return 'Telescope must not be enabled in production without an explicit access decision';
    }

    public function isApplicable(): bool
    {
        return class_exists('Laravel\\Telescope\\Telescope');
    }

    /**
     * Detection itself is production-gated, so findings keep their explicit
     * severities instead of using downgradeIfNotProduction().
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

        if (! filter_var($config->get('telescope.enabled', true), FILTER_VALIDATE_BOOLEAN)) {
            return;
        }

        /** @var Gate $gate */
        $gate = $this->app->make(Gate::class);

        if (! $gate->has('viewTelescope')) {
            yield new Finding(
                checkId: $this->id(),
                severity: Severity::Critical,
                message: 'Telescope is enabled in production without an explicit viewTelescope gate — the operator has not made an explicit access decision. Set TELESCOPE_ENABLED=false or define the viewTelescope gate.',
            );

            return;
        }

        yield new Finding(
            checkId: $this->id(),
            severity: Severity::Medium,
            message: 'Telescope is enabled in production — verify the viewTelescope gate restricts access; consider TELESCOPE_ENABLED=false.',
        );
    }
}

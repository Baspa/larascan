<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Config;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class DebugBlacklistCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'config.debug-blacklist';
    }

    public function category(): Category
    {
        return Category::Config;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'app.debug_blacklist must redact sensitive env keys when debug is on';
    }

    public function isApplicable(): bool
    {
        /** @var Repository $config */
        $config = $this->app->make('config');

        return (bool) filter_var($config->get('app.debug'), FILTER_VALIDATE_BOOLEAN);
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        /** @var Repository $config */
        $config = $this->app->make('config');

        $blacklist = $config->get('app.debug_blacklist', []);
        $hasEntries = is_array($blacklist) && array_filter($blacklist, fn ($v) => is_array($v) && $v !== []) !== [];

        if ($hasEntries) {
            return;
        }

        $env = (string) ($config->get('app.env') ?? '');

        yield new Finding(
            checkId: $this->id(),
            severity: $this->severity()->downgradeIfNotProduction($env),
            message: 'app.debug_blacklist is empty — Whoops debug pages will expose all env, server and request data when an exception fires.',
        );
    }
}

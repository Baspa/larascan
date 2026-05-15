<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Auth;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class SanctumExpirationCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'auth.sanctum-expiration';
    }

    public function category(): Category
    {
        return Category::Auth;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'Sanctum API tokens should expire to limit blast radius of leaks';
    }

    public function isApplicable(): bool
    {
        return class_exists('Laravel\\Sanctum\\Sanctum');
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        /** @var Repository $config */
        $config = $this->app->make('config');

        if ($config->get('sanctum.expiration') === null) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: 'sanctum.expiration is null — issued API tokens never expire. Set SANCTUM_TOKEN_EXPIRATION_MINUTES or config(\'sanctum.expiration\') to a sensible value (e.g. 1440 for one day).',
            );
        }
    }
}

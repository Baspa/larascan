<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Auth;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class JwtMissingExpirationCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'auth.jwt-missing-expiration';
    }

    public function category(): Category
    {
        return Category::Auth;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'JWT tokens must have a TTL — otherwise issued tokens are valid forever';
    }

    public function isApplicable(): bool
    {
        return class_exists('Tymon\\JWTAuth\\JWT');
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        if (! $this->isApplicable()) {
            return;
        }

        /** @var Repository $config */
        $config = $this->app->make('config');
        $ttl = $config->get('jwt.ttl');

        if ($ttl === null || $ttl === 0 || $ttl === '0') {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: 'jwt.ttl is null or 0 — issued JWT tokens never expire. Set JWT_TTL in .env to a sensible value (e.g. 60 for one hour).',
            );
        }
    }
}

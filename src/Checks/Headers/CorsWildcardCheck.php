<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Headers;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class CorsWildcardCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'headers.cors-wildcard';
    }

    public function category(): Category
    {
        return Category::Headers;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'CORS allowed_origins must not be wildcard with credentials enabled';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        /** @var Repository $config */
        $config = $this->app->make('config');

        $origins = $config->get('cors.allowed_origins');
        $credentials = filter_var($config->get('cors.supports_credentials'), FILTER_VALIDATE_BOOLEAN);

        if (! $credentials) {
            return;
        }

        $hasWildcard = $origins === '*'
            || (is_array($origins) && in_array('*', $origins, true));

        if ($hasWildcard) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: 'CORS combines wildcard allowed_origins (*) with supports_credentials=true — browsers reject this combination, and it signals a critical misconfiguration intent.',
            );
        }
    }
}

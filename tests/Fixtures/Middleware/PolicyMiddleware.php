<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tests\Fixtures\Middleware;

use Closure;

/**
 * Stands in for a package middleware that apps subclass, e.g. AddCspHeaders.
 */
class PolicyMiddleware
{
    public function handle(mixed $request, Closure $next): mixed
    {
        return $next($request);
    }
}

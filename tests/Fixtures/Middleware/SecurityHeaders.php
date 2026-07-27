<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tests\Fixtures\Middleware;

use Closure;

/**
 * A middleware that sets HSTS but is named nothing like it — the shape that made
 * HstsCheck report a false positive.
 */
final class SecurityHeaders
{
    public function handle(mixed $request, Closure $next): mixed
    {
        $response = $next($request);

        $response->headers->set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');

        return $response;
    }
}

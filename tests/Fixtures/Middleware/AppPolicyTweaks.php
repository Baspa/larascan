<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tests\Fixtures\Middleware;

use Closure;

/**
 * The shape that broke name matching: a subclass registered in place of its
 * parent, whose own name shares no substring with it.
 */
final class AppPolicyTweaks extends PolicyMiddleware
{
    public function handle(mixed $request, Closure $next): mixed
    {
        return parent::handle($request, $next);
    }
}

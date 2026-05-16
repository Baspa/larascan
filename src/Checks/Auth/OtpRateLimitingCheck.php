<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Auth;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Throwable;

final class OtpRateLimitingCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'auth.otp-rate-limiting';
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
        return 'OTP / 2FA verification routes must have throttle middleware';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        try {
            /** @var Router $router */
            $router = $this->app->make(Router::class);
            $routes = $router->getRoutes()->getRoutes();
        } catch (Throwable) {
            return;
        }

        foreach ($routes as $route) {
            if (! $route instanceof Route) {
                continue;
            }

            $haystack = strtolower($route->uri().' '.((string) $route->getName()));
            if (preg_match('~(otp|2fa|two-factor)~', $haystack) !== 1) {
                continue;
            }

            if ($this->hasThrottle($route->middleware())) {
                continue;
            }

            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: "OTP/2FA route {$route->uri()} has no throttle middleware — brute-force protection missing. Add ->middleware('throttle:6,1').",
            );
        }
    }

    /**
     * @param  array<int, string>  $middleware
     */
    private function hasThrottle(array $middleware): bool
    {
        foreach ($middleware as $entry) {
            if (is_string($entry) && str_starts_with($entry, 'throttle')) {
                return true;
            }
        }

        return false;
    }
}

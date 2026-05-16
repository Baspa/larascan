<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Auth;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Throwable;

final class RegistrationRateLimitCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'auth.registration-rate-limit';
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
        return 'Registration route must have throttle middleware to prevent automated signup abuse';
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

        /** @var Repository $config */
        $config = $this->app->make('config');
        $env = (string) ($config->get('app.env') ?? '');

        foreach ($routes as $route) {
            if (! $route instanceof Route) {
                continue;
            }

            $haystack = strtolower($route->uri().' '.((string) $route->getName()));
            if (preg_match('~(register|signup)~', $haystack) !== 1) {
                continue;
            }

            if ($this->hasThrottle($route->middleware())) {
                continue;
            }

            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity()->downgradeIfNotProduction($env),
                message: "Registration route {$route->uri()} has no throttle middleware — automated signups unmitigated. Add ->middleware('throttle:5,1').",
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

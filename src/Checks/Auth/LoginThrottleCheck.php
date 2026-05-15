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

final class LoginThrottleCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'auth.login-throttle';
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
        return 'Login routes must have throttle middleware to mitigate brute-force attacks';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        /** @var Router $router */
        $router = $this->app->make(Router::class);

        foreach ($router->getRoutes()->getRoutes() as $route) {
            if (! $route instanceof Route) {
                continue;
            }

            $uri = $route->uri();
            $name = (string) ($route->getName() ?? '');

            $isLoginRoute = stripos($uri, 'login') !== false
                || ($name !== '' && stripos($name, 'login') !== false);

            if (! $isLoginRoute) {
                continue;
            }

            $middleware = $route->middleware();
            $hasThrottle = false;

            foreach ($middleware as $entry) {
                if (! is_string($entry)) {
                    continue;
                }

                if (str_starts_with($entry, 'throttle')) {
                    $hasThrottle = true;
                    break;
                }
            }

            if ($hasThrottle) {
                continue;
            }

            $methods = $route->methods();
            $method = $methods[0] ?? 'GET';
            $routeName = $name !== '' ? $name : '(unnamed)';

            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: "Login route '{$routeName}' ({$method} {$uri}) has no throttle middleware — brute-force attacks unmitigated. Add ->middleware('throttle:5,1').",
            );
        }
    }
}

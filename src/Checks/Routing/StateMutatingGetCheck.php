<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Routing;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Throwable;

final class StateMutatingGetCheck extends AbstractCheck
{
    /** @var array<int, string> */
    private const MUTATING_METHODS = ['destroy', 'delete', 'remove', 'deactivate', 'disable'];

    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'routing.state-mutating-get';
    }

    public function category(): Category
    {
        return Category::Routing;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'GET routes must not invoke state-mutating controller actions (destroy/delete/remove/deactivate/disable)';
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

            if (! in_array('GET', $route->methods(), true)) {
                continue;
            }

            $action = $route->getActionName();
            if (! is_string($action) || ! str_contains($action, '@')) {
                continue;
            }

            $method = strtolower(substr($action, strrpos($action, '@') + 1));
            if (! in_array($method, self::MUTATING_METHODS, true)) {
                continue;
            }

            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: "GET route {$route->uri()} invokes {$action} — state mutation via GET is unsafe (browser prefetch, CSRF). Use DELETE/POST.",
            );
        }
    }
}

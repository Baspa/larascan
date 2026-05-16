<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Routing;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Throwable;

final class ApiHttpOnlyCheck extends AbstractCheck
{
    /** @var array<int, string> */
    private const HTTPS_MIDDLEWARE_FRAGMENTS = ['force.https', 'forcehttps', 'requirehttps', 'redirecttohttps'];

    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'routing.api-http-only';
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
        return 'API routes must enforce HTTPS — APP_URL is http and no HTTPS middleware is registered';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        /** @var Repository $config */
        $config = $this->app->make('config');
        $url = (string) ($config->get('app.url') ?? '');
        if (str_starts_with($url, 'https://')) {
            return;
        }

        try {
            /** @var Router $router */
            $router = $this->app->make(Router::class);
            $routes = $router->getRoutes()->getRoutes();
        } catch (Throwable) {
            return;
        }

        $env = (string) ($config->get('app.env') ?? '');

        foreach ($routes as $route) {
            if (! $route instanceof Route) {
                continue;
            }
            if (! str_starts_with($route->uri(), 'api/')) {
                continue;
            }
            if ($this->hasHttpsMiddleware($route->middleware())) {
                continue;
            }

            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity()->downgradeIfNotProduction($env),
                message: "API route {$route->uri()} has no HTTPS-enforcing middleware and APP_URL is {$url}. Add 'force.https' middleware or set APP_URL to https://.",
            );
        }
    }

    /**
     * @param  array<int, string>  $middleware
     */
    private function hasHttpsMiddleware(array $middleware): bool
    {
        foreach ($middleware as $entry) {
            if (! is_string($entry)) {
                continue;
            }
            $lower = strtolower($entry);
            foreach (self::HTTPS_MIDDLEWARE_FRAGMENTS as $fragment) {
                if (str_contains($lower, $fragment)) {
                    return true;
                }
            }
        }

        return false;
    }
}

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

final class SignedRoutesVerifyCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'auth.signed-routes-verify';
    }

    public function category(): Category
    {
        return Category::Auth;
    }

    public function severity(): Severity
    {
        return Severity::Low;
    }

    public function name(): string
    {
        return 'Email verification routes must use the signed middleware to prevent URL tampering';
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

            $haystack = strtolower($name.' '.$uri);

            $isVerifyRoute = str_contains($haystack, 'verify') && str_contains($haystack, 'email');

            if (! $isVerifyRoute) {
                continue;
            }

            $middleware = $route->middleware();
            $hasSigned = false;

            foreach ($middleware as $entry) {
                if (! is_string($entry)) {
                    continue;
                }

                if ($entry === 'signed' || str_starts_with($entry, 'signed:') || str_starts_with($entry, 'signed ')) {
                    $hasSigned = true;
                    break;
                }
            }

            if ($hasSigned) {
                continue;
            }

            $routeName = $name !== '' ? $name : '(unnamed)';

            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: "Email verification route '{$routeName}' ({$uri}) is missing 'signed' middleware — URL parameters can be tampered with.",
            );
        }
    }
}

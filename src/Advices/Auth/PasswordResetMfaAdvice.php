<?php

declare(strict_types=1);

namespace Baspa\Larascan\Advices\Auth;

use Baspa\Larascan\Support\AbstractAdvice;
use Baspa\Larascan\Support\AdviceEvidence;
use Baspa\Larascan\Support\AdviceOutcome;
use Baspa\Larascan\Support\Category;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Throwable;

final class PasswordResetMfaAdvice extends AbstractAdvice
{
    private const MFA_MARKERS = ['2fa', 'two-factor', 'twofactor', 'otp', 'mfa', 'verified'];

    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'advise.password-reset-mfa';
    }

    public function category(): Category
    {
        return Category::Auth;
    }

    public function name(): string
    {
        return 'Password reset routes should require MFA — otherwise reset becomes an MFA bypass';
    }

    public function run(): AdviceOutcome
    {
        try {
            /** @var Router $router */
            $router = $this->app->make(Router::class);
            $routes = $router->getRoutes()->getRoutes();
        } catch (Throwable) {
            return AdviceOutcome::notSurfaced();
        }

        $evidence = [];
        foreach ($routes as $route) {
            if (! $route instanceof Route) {
                continue;
            }

            $name = (string) ($route->getName() ?? '');
            $uri = $route->uri();
            $haystack = strtolower($name.' '.$uri);

            $isResetRoute = in_array($name, ['password.update', 'password.confirm'], true)
                || preg_match('~password.*reset~', $haystack) === 1;

            if (! $isResetRoute) {
                continue;
            }

            if ($this->hasMfaMarker($route->middleware())) {
                continue;
            }

            $evidence[] = new AdviceEvidence(
                message: "Route '{$name}' ({$uri}) has no MFA-suggesting middleware",
            );
        }

        if ($evidence === []) {
            return AdviceOutcome::notSurfaced();
        }

        return AdviceOutcome::surfaced(
            sprintf('%d password-reset route(s) have no MFA-suggesting middleware.', count($evidence)),
            $evidence,
        );
    }

    /**
     * @param  array<int, string>  $middleware
     */
    private function hasMfaMarker(array $middleware): bool
    {
        foreach ($middleware as $entry) {
            if (! is_string($entry)) {
                continue;
            }
            $lower = strtolower($entry);
            foreach (self::MFA_MARKERS as $marker) {
                if (str_contains($lower, $marker)) {
                    return true;
                }
            }
        }

        return false;
    }
}

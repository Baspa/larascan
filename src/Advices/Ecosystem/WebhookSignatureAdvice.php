<?php

declare(strict_types=1);

namespace Baspa\Larascan\Advices\Ecosystem;

use Baspa\Larascan\Support\AbstractAdvice;
use Baspa\Larascan\Support\AdviceEvidence;
use Baspa\Larascan\Support\AdviceOutcome;
use Baspa\Larascan\Support\Category;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Throwable;

final class WebhookSignatureAdvice extends AbstractAdvice
{
    private const URI_PATTERN = '~webhook|hooks?/|callback~i';

    private const SIGNATURE_MARKERS = [
        'signed',
        'validatesignature',
        'verifywebhooksignature',
        'verifysignature',
        'webhook',
    ];

    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'advise.webhook-signature';
    }

    public function category(): Category
    {
        return Category::Ecosystem;
    }

    public function name(): string
    {
        return 'Webhook endpoints should verify request signatures — review unprotected ones by hand';
    }

    public function run(): AdviceOutcome
    {
        try {
            /** @var Router $router */
            $router = $this->app->make('router');
            $routes = $router->getRoutes()->getRoutes();
        } catch (Throwable) {
            return AdviceOutcome::notSurfaced();
        }

        $webhookRoutes = [];
        foreach ($routes as $route) {
            if (! $route instanceof Route) {
                continue;
            }

            if (! in_array('POST', $route->methods(), true)) {
                continue;
            }

            if (preg_match(self::URI_PATTERN, $route->uri()) === 1) {
                $webhookRoutes[] = $route;
            }
        }

        if ($webhookRoutes === []) {
            return AdviceOutcome::skipped('no webhook-looking POST routes registered');
        }

        $evidence = [];
        foreach ($webhookRoutes as $route) {
            if ($this->hasSignatureMiddleware($route)) {
                continue;
            }

            $evidence[] = new AdviceEvidence(
                message: "POST {$route->uri()} has no signature-verifying middleware — verify the payload signature (signed, ValidateSignature, or a vendor webhook middleware) or replay attacks and forged events go straight through",
            );
        }

        if ($evidence === []) {
            return AdviceOutcome::notSurfaced();
        }

        return AdviceOutcome::surfaced(
            sprintf('%d webhook route(s) have no signature-verifying middleware.', count($evidence)),
            $evidence,
        );
    }

    private function hasSignatureMiddleware(Route $route): bool
    {
        try {
            $middleware = $route->gatherMiddleware();
        } catch (Throwable) {
            $middleware = $route->middleware();
        }

        foreach ($middleware as $entry) {
            if (! is_string($entry)) {
                continue;
            }

            $lower = strtolower($entry);
            foreach (self::SIGNATURE_MARKERS as $marker) {
                if (str_contains($lower, $marker)) {
                    return true;
                }
            }
        }

        return false;
    }
}

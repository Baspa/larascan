<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Headers;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class CspUnsafeInlineCheck extends AbstractCheck
{
    private const RISKY_TOKENS = ['unsafe-inline', 'unsafe-eval'];

    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'headers.csp-unsafe-inline';
    }

    public function category(): Category
    {
        return Category::Headers;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'CSP must not use unsafe-inline or unsafe-eval';
    }

    public function isApplicable(): bool
    {
        return class_exists('Spatie\\Csp\\AddCspHeaders');
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        /** @var Repository $config */
        $config = $this->app->make('config');

        $policy = $config->get('csp.policy');
        $directives = $config->get('csp.directives');

        $haystack = '';
        if (is_string($policy)) {
            $haystack .= ' '.$policy;
        }
        if (is_array($directives)) {
            $haystack .= ' '.json_encode($directives);
        }

        $haystackLower = strtolower($haystack);
        foreach (self::RISKY_TOKENS as $token) {
            if (str_contains($haystackLower, $token)) {
                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: "CSP contains '{$token}' — this voids most of CSP's XSS protection. Use nonces or hashes instead.",
                );
            }
        }
    }
}

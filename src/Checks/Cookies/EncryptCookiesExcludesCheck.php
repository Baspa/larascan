<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Cookies;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Cookie\Middleware\EncryptCookies;
use ReflectionClass;
use Throwable;

final class EncryptCookiesExcludesCheck extends AbstractCheck
{
    private const SENSITIVE_PATTERNS = [
        'session',
        'remember',
        'csrf',
        'xsrf',
        'auth',
        'token',
        'secret',
        'key',
    ];

    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'cookies.encrypt-excludes';
    }

    public function category(): Category
    {
        return Category::Cookies;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'Sensitive cookies must not be in EncryptCookies::$except';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        try {
            $middleware = $this->app->make(EncryptCookies::class);
        } catch (Throwable) {
            return;
        }

        $reflection = new ReflectionClass($middleware);
        if (! $reflection->hasProperty('except')) {
            return;
        }

        $exceptValue = $reflection->getProperty('except')->getValue($middleware);
        if (! is_array($exceptValue)) {
            return;
        }

        foreach ($exceptValue as $cookieName) {
            if (! is_string($cookieName)) {
                continue;
            }

            $matched = $this->matchedPattern($cookieName);
            if ($matched === null) {
                continue;
            }

            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: "Cookie '{$cookieName}' is excluded from encryption but matches the sensitive pattern '{$matched}'.",
            );
        }
    }

    private function matchedPattern(string $cookieName): ?string
    {
        $lower = strtolower($cookieName);
        foreach (self::SENSITIVE_PATTERNS as $pattern) {
            if (str_contains($lower, $pattern)) {
                return $pattern;
            }
        }

        return null;
    }
}

<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Cookies;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Cookie\Middleware\EncryptCookies;
use ReflectionClass;
use Throwable;

final class EncryptCookiesMiddlewareCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'cookies.encrypt-middleware';
    }

    public function category(): Category
    {
        return Category::Cookies;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'EncryptCookies middleware must be registered';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        try {
            $kernel = $this->app->make(Kernel::class);
        } catch (Throwable) {
            return;
        }

        $middlewareNames = $this->collectMiddlewareNames($kernel);

        $hasEncryptCookies = false;
        foreach ($middlewareNames as $name) {
            if (
                $name === EncryptCookies::class
                || is_subclass_of($name, EncryptCookies::class)
            ) {
                $hasEncryptCookies = true;
                break;
            }
        }

        if (! $hasEncryptCookies) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: 'EncryptCookies middleware is not registered — cookies are sent unencrypted to the browser, exposing session and remember-me data in plain text.',
            );
        }
    }

    /**
     * @return array<int, string>
     */
    private function collectMiddlewareNames(object $kernel): array
    {
        $names = [];

        foreach (['middleware', 'middlewareGroups', 'middlewarePriority'] as $propName) {
            try {
                $reflection = new ReflectionClass($kernel);
                if (! $reflection->hasProperty($propName)) {
                    continue;
                }
                $prop = $reflection->getProperty($propName);
                $value = $prop->getValue($kernel);
                if (! is_array($value)) {
                    continue;
                }
                $names = array_merge($names, $this->flatten($value));
            } catch (Throwable) {
                continue;
            }
        }

        return $names;
    }

    /**
     * @param  array<mixed>  $value
     * @return array<int, string>
     */
    private function flatten(array $value): array
    {
        $out = [];
        foreach ($value as $item) {
            if (is_string($item)) {
                $out[] = $item;
            } elseif (is_array($item)) {
                foreach ($this->flatten($item) as $sub) {
                    $out[] = $sub;
                }
            }
        }

        return $out;
    }
}

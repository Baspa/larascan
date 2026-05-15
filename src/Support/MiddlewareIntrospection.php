<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

use Illuminate\Contracts\Http\Kernel;
use ReflectionClass;
use Throwable;

final class MiddlewareIntrospection
{
    /**
     * Returns the flat list of every middleware FQCN registered in the HTTP kernel.
     *
     * @return array<int, string>
     */
    public static function listMiddlewareFqcns(object $app): array
    {
        try {
            // @phpstan-ignore-next-line — duck-typed for testability
            $kernel = $app->make(Kernel::class);
        } catch (Throwable) {
            return [];
        }

        $names = [];
        foreach (['middleware', 'middlewareGroups', 'middlewarePriority'] as $prop) {
            try {
                $reflection = new ReflectionClass($kernel);
                if (! $reflection->hasProperty($prop)) {
                    continue;
                }
                $value = $reflection->getProperty($prop)->getValue($kernel);
                if (! is_array($value)) {
                    continue;
                }
                $names = array_merge($names, self::flatten($value));
            } catch (Throwable) {
                continue;
            }
        }

        return $names;
    }

    /**
     * @param  array<int, string>  $patterns
     */
    public static function anyMatching(object $app, array $patterns): bool
    {
        foreach (self::listMiddlewareFqcns($app) as $fqcn) {
            $lower = strtolower($fqcn);
            foreach ($patterns as $pattern) {
                if (str_contains($lower, strtolower($pattern))) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @param  array<mixed>  $value
     * @return array<int, string>
     */
    private static function flatten(array $value): array
    {
        $out = [];
        foreach ($value as $item) {
            if (is_string($item)) {
                $out[] = $item;
            } elseif (is_array($item)) {
                foreach (self::flatten($item) as $sub) {
                    $out[] = $sub;
                }
            }
        }

        return $out;
    }
}

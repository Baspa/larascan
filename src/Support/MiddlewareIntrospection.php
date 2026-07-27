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
     * True when any registered middleware is $baseClass or extends it.
     *
     * Name matching alone misses the common case of an app subclassing a
     * package's middleware to special-case a few routes — the subclass still
     * does the work, but its name need not contain the parent's.
     */
    public static function anySubclassOf(object $app, string $baseClass): bool
    {
        foreach (self::listMiddlewareFqcns($app) as $fqcn) {
            $class = self::classPart($fqcn);

            if ($class !== '' && class_exists($class) && is_a($class, $baseClass, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * True when the source of any registered middleware mentions $needle.
     *
     * For headers that no package owns, the class name says nothing — an app
     * may set Strict-Transport-Security from a middleware called anything at
     * all. Reading the declaring file is the only signal available short of
     * issuing a real request, which is what the probe command is for.
     */
    public static function anyMentioningInSource(object $app, string $needle): bool
    {
        foreach (self::listMiddlewareFqcns($app) as $fqcn) {
            $class = self::classPart($fqcn);

            if ($class === '' || ! class_exists($class)) {
                continue;
            }

            // class_exists() has already autoloaded it, so reflection cannot throw
            // here. getFileName() still returns false for internal classes.
            $file = (new ReflectionClass($class))->getFileName();

            if ($file === false) {
                continue;
            }

            $source = @file_get_contents($file);

            if ($source !== false && stripos($source, $needle) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Strips any middleware parameters, e.g. "Throttle:api" -> "Throttle".
     */
    private static function classPart(string $fqcn): string
    {
        $position = strpos($fqcn, ':');

        return $position === false ? $fqcn : substr($fqcn, 0, $position);
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

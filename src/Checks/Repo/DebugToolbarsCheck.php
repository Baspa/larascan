<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Repo;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;

final class DebugToolbarsCheck extends AbstractCheck
{
    /**
     * @var array<int, string>
     */
    private const DEBUG_PACKAGES = [
        'barryvdh/laravel-debugbar',
        'laravel/telescope',
        'itsgoingd/clockwork',
        'spatie/laravel-ray',
    ];

    public function __construct(
        private readonly string $basePath,
    ) {}

    public function id(): string
    {
        return 'repo.debug-toolbars';
    }

    public function category(): Category
    {
        return Category::Repo;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'Debug tools must live in require-dev so they never ship to production';
    }

    public function isApplicable(): bool
    {
        return is_file($this->basePath.'/composer.json');
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        $contents = (string) file_get_contents($this->basePath.'/composer.json');
        if ($contents === '') {
            return;
        }

        /** @var mixed $decoded */
        $decoded = json_decode($contents, true);
        if (! is_array($decoded)) {
            return;
        }

        $require = $decoded['require'] ?? [];
        if (! is_array($require)) {
            return;
        }

        foreach (self::DEBUG_PACKAGES as $package) {
            if (! array_key_exists($package, $require)) {
                continue;
            }

            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: "Debug tool '{$package}' is in `require` (production deps) instead of `require-dev` — runs and exposes data in production.",
            );
        }
    }
}

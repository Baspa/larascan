<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Dependencies;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;

final class MinimumStabilityDevCheck extends AbstractCheck
{
    public function __construct(
        private readonly string $basePath,
    ) {}

    public function id(): string
    {
        return 'dependencies.minimum-stability-dev';
    }

    public function category(): Category
    {
        return Category::Dependencies;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'composer.json minimum-stability is dev without prefer-stable';
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
        $path = $this->basePath.'/composer.json';
        $raw = @file_get_contents($path);

        if ($raw === false) {
            return;
        }

        /** @var mixed $decoded */
        $decoded = json_decode($raw, true);

        if (! is_array($decoded)) {
            return;
        }

        $minimumStability = $decoded['minimum-stability'] ?? null;
        $preferStable = $decoded['prefer-stable'] ?? null;

        if ($minimumStability === 'dev' && $preferStable !== true) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: "composer.json minimum-stability is 'dev' without prefer-stable=true — production may pull unstable releases. Set prefer-stable: true or use stability constraints per-package.",
            );
        }
    }
}

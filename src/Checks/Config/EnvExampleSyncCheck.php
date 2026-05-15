<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Config;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;

final class EnvExampleSyncCheck extends AbstractCheck
{
    public function __construct(
        private readonly string $basePath,
    ) {}

    public function id(): string
    {
        return 'config.env-example-sync';
    }

    public function category(): Category
    {
        return Category::Config;
    }

    public function severity(): Severity
    {
        return Severity::Low;
    }

    public function name(): string
    {
        return '.env and .env.example must declare the same keys';
    }

    public function isApplicable(): bool
    {
        return is_file($this->basePath.'/.env') && is_file($this->basePath.'/.env.example');
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        $envKeys = $this->keysOf($this->basePath.'/.env');
        $exampleKeys = $this->keysOf($this->basePath.'/.env.example');

        $missingFromExample = array_diff($envKeys, $exampleKeys);
        if ($missingFromExample !== []) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: 'Keys present in .env but missing from .env.example: '.implode(', ', $missingFromExample),
            );
        }

        $missingFromEnv = array_diff($exampleKeys, $envKeys);
        if ($missingFromEnv !== []) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: 'Keys present in .env.example but missing from .env: '.implode(', ', $missingFromEnv),
            );
        }
    }

    /**
     * @return array<int, string>
     */
    private function keysOf(string $path): array
    {
        $contents = (string) file_get_contents($path);
        $keys = [];
        foreach (explode("\n", $contents) as $line) {
            $trimmed = trim($line);
            if ($trimmed === '' || str_starts_with($trimmed, '#')) {
                continue;
            }
            $equalsPos = strpos($trimmed, '=');
            if ($equalsPos === false) {
                continue;
            }
            $keys[] = trim(substr($trimmed, 0, $equalsPos));
        }

        return array_values(array_unique(array_filter($keys, fn ($k) => $k !== '')));
    }
}

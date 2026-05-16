<?php

declare(strict_types=1);

namespace Baspa\Larascan\Advices\Crypto;

use Baspa\Larascan\Support\AbstractAdvice;
use Baspa\Larascan\Support\AdviceEvidence;
use Baspa\Larascan\Support\AdviceOutcome;
use Baspa\Larascan\Support\Category;

final class StagingKeyInProductionAdvice extends AbstractAdvice
{
    /** @var array<int, string> */
    private const TEST_PREFIXES = ['sk_test_', 'pk_test_', 'whsec_test_'];

    public function __construct(
        private readonly string $basePath,
    ) {}

    public function id(): string
    {
        return 'advise.staging-key-in-production';
    }

    public function category(): Category
    {
        return Category::Crypto;
    }

    public function name(): string
    {
        return 'Test-prefixed API keys should not be present alongside APP_ENV=production';
    }

    public function run(): AdviceOutcome
    {
        $envPath = $this->basePath.'/.env';
        if (! is_file($envPath)) {
            return AdviceOutcome::skipped('.env file not present');
        }

        $contents = (string) file_get_contents($envPath);
        $lines = explode("\n", $contents);

        $isProduction = false;
        $matches = [];

        foreach ($lines as $rawLine) {
            $line = trim($rawLine);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            if (preg_match('/^([A-Z0-9_]+)\s*=\s*(.+)$/', $line, $captured) !== 1) {
                continue;
            }
            $key = $captured[1];
            $value = trim($captured[2], "\"'");

            if ($key === 'APP_ENV' && strtolower($value) === 'production') {
                $isProduction = true;

                continue;
            }

            foreach (self::TEST_PREFIXES as $prefix) {
                if (str_starts_with($value, $prefix)) {
                    $truncated = substr($value, 0, 12).'…';
                    $matches[] = new AdviceEvidence(
                        message: "{$key} starts with {$prefix} (value: {$truncated})",
                    );

                    continue 2;
                }
            }

            if (str_contains($value, '_test_')) {
                $truncated = substr($value, 0, 12).'…';
                $matches[] = new AdviceEvidence(
                    message: "{$key} contains '_test_' (value: {$truncated})",
                );
            }
        }

        if ($matches === []) {
            return AdviceOutcome::notSurfaced();
        }

        $summary = sprintf('%d test-prefixed API key(s) found in .env.', count($matches));
        if ($isProduction) {
            $summary .= ' **likely active in production**';
        }

        return AdviceOutcome::surfaced($summary, $matches);
    }
}

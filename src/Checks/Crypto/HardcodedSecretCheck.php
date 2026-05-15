<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Crypto;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use PhpParser\Node\Scalar\String_;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class HardcodedSecretCheck extends AbstractCheck
{
    /**
     * Named regex patterns. The 'aws-secret-key' pattern is also gated by entropy
     * because the regex alone (40-char base64-ish) has a very high false-positive rate.
     *
     * @var array<string, string>
     */
    private const PATTERNS = [
        'aws-access-key' => '/^AKIA[0-9A-Z]{16}$/',
        'aws-secret-key' => '/^[A-Za-z0-9\/+=]{40}$/',
        'stripe-key' => '/^(?:r|s)k_(?:live|test)_[a-zA-Z0-9]{24,}$/',
        'github-pat' => '/^ghp_[a-zA-Z0-9]{36}$/',
        'github-oauth' => '/^gho_[a-zA-Z0-9]{36}$/',
        'slack-bot-token' => '/^xoxb-[a-zA-Z0-9-]+$/',
        'slack-user-token' => '/^xoxp-[a-zA-Z0-9-]+$/',
        'jwt' => '/^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/',
    ];

    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'crypto.hardcoded-secret';
    }

    public function category(): Category
    {
        return Category::Crypto;
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function name(): string
    {
        return 'Hardcoded secret detected in source code';
    }

    public function isApplicable(): bool
    {
        return is_dir($this->appPath);
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        $finder = new NodeFinder;

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->appPath, RecursiveDirectoryIterator::SKIP_DOTS),
        );

        foreach ($iterator as $file) {
            if (! $file instanceof SplFileInfo || ! $file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }

            $ast = $this->parser->parse($file->getPathname());
            if ($ast === null) {
                continue;
            }

            /** @var array<int, String_> $strings */
            $strings = $finder->findInstanceOf($ast, String_::class);

            foreach ($strings as $string) {
                $value = $string->value;

                // Skip likely class names / FQCNs.
                if (str_contains($value, '\\')) {
                    continue;
                }

                $patternMatched = $this->matchPattern($value);
                if ($patternMatched === null) {
                    continue;
                }

                $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());
                $line = $string->getStartLine();

                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: "Possible hardcoded secret (pattern '{$patternMatched}') — move to .env.",
                    file: $relative,
                    line: $line,
                );
            }
        }
    }

    /**
     * Return the matched pattern name, or null if no patterns match.
     */
    private function matchPattern(string $value): ?string
    {
        foreach (self::PATTERNS as $name => $regex) {
            if (preg_match($regex, $value) !== 1) {
                continue;
            }

            // aws-secret-key is FP-prone — gate it behind an entropy threshold.
            if ($name === 'aws-secret-key' && $this->shannonEntropy($value) < 4.5) {
                continue;
            }

            return $name;
        }

        // Generic high-entropy fallback.
        if (
            strlen($value) >= 32
            && ! preg_match('/\s/', $value)
            && preg_match('/[A-Za-z]/', $value) === 1
            && preg_match('/[0-9]/', $value) === 1
            && $this->shannonEntropy($value) >= 4.5
        ) {
            return 'high-entropy';
        }

        return null;
    }

    private function shannonEntropy(string $value): float
    {
        $length = strlen($value);
        if ($length === 0) {
            return 0.0;
        }

        /** @var array<string, int> $counts */
        $counts = [];
        for ($i = 0; $i < $length; $i++) {
            $char = $value[$i];
            $counts[$char] = ($counts[$char] ?? 0) + 1;
        }

        $entropy = 0.0;
        foreach ($counts as $count) {
            $p = $count / $length;
            $entropy -= $p * log($p, 2);
        }

        return $entropy;
    }
}

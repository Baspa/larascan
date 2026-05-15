<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Php;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;

final class PublicSensitiveFilesCheck extends AbstractCheck
{
    /**
     * Patterns to look for in public/. Mix of literal filenames and globs.
     *
     * @var array<int, string>
     */
    private const PATTERNS = [
        '.env',
        '.git',
        '*.sql',
        '*.sql.gz',
        '*.bak',
        '*.swp',
        'composer.json',
        'composer.lock',
    ];

    public function __construct(
        private readonly string $publicPath,
    ) {}

    public function id(): string
    {
        return 'php.public-sensitive-files';
    }

    public function category(): Category
    {
        return Category::Php;
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function name(): string
    {
        return 'Sensitive files in public/ leak infrastructure data';
    }

    public function isApplicable(): bool
    {
        return is_dir($this->publicPath);
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        $seen = [];

        foreach (self::PATTERNS as $pattern) {
            $matches = glob($this->publicPath.DIRECTORY_SEPARATOR.$pattern, GLOB_NOSORT) ?: [];

            foreach ($matches as $match) {
                if (isset($seen[$match])) {
                    continue;
                }
                $seen[$match] = true;

                $filename = basename($match);

                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: "Sensitive file '{$filename}' found inside public/ — accessible at https://yoursite/{$filename}, leaking infrastructure data.",
                    file: 'public/'.$filename,
                );
            }
        }
    }
}

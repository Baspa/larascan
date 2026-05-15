<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Files;

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

final class UploadMimesValidationCheck extends AbstractCheck
{
    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'files.upload-mimes-validation';
    }

    public function category(): Category
    {
        return Category::Files;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return '`extensions:` validation rule checks filename only — use `mimes:` for MIME validation';
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
                if (! str_contains($string->value, 'extensions:')) {
                    continue;
                }

                $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());
                $line = $string->getStartLine();

                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: '`extensions:` validation rule checks only filename extension which attackers can spoof — use `mimes:` rule to validate MIME type.',
                    file: $relative,
                    line: $line,
                );
            }
        }
    }
}

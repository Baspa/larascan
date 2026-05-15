<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Xss;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class UrlJavascriptProtocolCheck extends AbstractCheck
{
    public function __construct(
        private readonly string $viewsPath,
    ) {}

    public function id(): string
    {
        return 'xss.url-javascript-protocol';
    }

    public function category(): Category
    {
        return Category::Xss;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'javascript: URL in Blade view is an XSS sink';
    }

    public function isApplicable(): bool
    {
        return is_dir($this->viewsPath);
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->viewsPath, RecursiveDirectoryIterator::SKIP_DOTS),
        );

        foreach ($iterator as $file) {
            if (! $file instanceof SplFileInfo || ! $file->isFile()) {
                continue;
            }

            if (! str_ends_with($file->getFilename(), '.blade.php')) {
                continue;
            }

            $contents = @file_get_contents($file->getPathname());
            if ($contents === false) {
                continue;
            }

            $count = preg_match_all('/(?:href|src)\s*=\s*["\']\s*javascript:/i', $contents, $matches, PREG_OFFSET_CAPTURE);
            if ($count === false || $count === 0) {
                continue;
            }

            $relative = str_replace(dirname($this->viewsPath).DIRECTORY_SEPARATOR, '', $file->getPathname());

            foreach ($matches[0] as $match) {
                $offset = $match[1];
                $line = substr_count(substr($contents, 0, $offset), "\n") + 1;

                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: 'javascript: URL is an XSS sink — replace with onclick handler bound via JavaScript.',
                    file: $relative,
                    line: $line,
                );
            }
        }
    }
}

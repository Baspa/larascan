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

final class BladeUnescapedCheck extends AbstractCheck
{
    public function __construct(
        private readonly string $viewsPath,
    ) {}

    public function id(): string
    {
        return 'xss.blade-unescaped';
    }

    public function category(): Category
    {
        return Category::Xss;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'Blade {!! ... !!} unescaped output with PHP variable is XSS-prone';
    }

    public function isApplicable(): bool
    {
        return is_dir($this->viewsPath);
    }

    /**
     * @return iterable<Finding>
     */
    /**
     * True when the whole expression is one call to a function that already
     * neutralises HTML, so {!! !!} is not reintroducing an XSS sink.
     *
     * Laravel's own published plain-text mail layout is {!! strip_tags($slot) !!}
     * on every line, so without this every app that runs `vendor:publish` on the
     * mail views inherits four high-severity findings it cannot act on — the
     * body is text/plain, and escaping it would emit literal &amp; to readers.
     */
    private static function isSanitized(string $expression): bool
    {
        if (preg_match('/^\s*(?:strip_tags|e|htmlspecialchars|htmlentities)\s*\((.*)\)\s*$/s', $expression, $m) !== 1) {
            return false;
        }

        // Guard against 'e($a) . $b', where the trailing ")" closes the first
        // call rather than wrapping the whole expression.
        $depth = 0;
        foreach (str_split($m[1]) as $char) {
            $depth += match ($char) {
                '(' => 1,
                ')' => -1,
                default => 0,
            };

            if ($depth < 0) {
                return false;
            }
        }

        return $depth === 0;
    }

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

            $count = preg_match_all('/\{!!\s*(.+?)\s*!!\}/s', $contents, $matches, PREG_OFFSET_CAPTURE);
            if ($count === false || $count === 0) {
                continue;
            }

            $relative = str_replace(dirname($this->viewsPath).DIRECTORY_SEPARATOR, '', $file->getPathname());

            foreach ($matches[1] as $match) {
                $expression = $match[0];
                $offset = $match[1];

                if (! str_contains($expression, '$')) {
                    continue;
                }

                if (self::isSanitized($expression)) {
                    continue;
                }

                $line = substr_count(substr($contents, 0, $offset), "\n") + 1;

                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: 'Blade {!! ... !!} unescaped output containing PHP variable — potential XSS if variable holds user input. Use {{ }} for HTML-escaped output.',
                    file: $relative,
                    line: $line,
                );
            }
        }
    }
}

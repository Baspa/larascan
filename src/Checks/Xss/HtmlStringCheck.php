<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Xss;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use PhpParser\Node;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Name;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class HtmlStringCheck extends AbstractCheck
{
    /**
     * @var array<int, string>
     */
    private const HTML_STRING_NAMES = [
        'HtmlString',
        'Illuminate\Support\HtmlString',
    ];

    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'xss.html-string';
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
        return 'HtmlString instantiation produces unescaped HTML — verify input is trusted';
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

            /** @var array<int, New_> $news */
            $news = $finder->find($ast, function (Node $node): bool {
                if (! $node instanceof New_) {
                    return false;
                }

                if (! $node->class instanceof Name) {
                    return false;
                }

                $name = $node->class->toString();
                $normalized = ltrim($name, '\\');

                return in_array($normalized, self::HTML_STRING_NAMES, true);
            });

            foreach ($news as $new) {
                $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());

                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: 'HtmlString instantiation produces unescaped HTML — verify input is trusted/sanitized.',
                    file: $relative,
                    line: $new->getStartLine(),
                );
            }
        }
    }
}

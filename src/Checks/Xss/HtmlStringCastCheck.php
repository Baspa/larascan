<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Xss;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use PhpParser\Node;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ArrayItem;
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class HtmlStringCastCheck extends AbstractCheck
{
    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'xss.htmlstring-cast';
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
        return 'Eloquent HtmlString casts auto-render attribute output unescaped — XSS source';
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

            /** @var array<int, Array_> $arrays */
            $arrays = $finder->findInstanceOf($ast, Array_::class);

            foreach ($arrays as $array) {
                foreach ($array->items as $item) {
                    if (! $item instanceof ArrayItem) {
                        continue;
                    }
                    if (! $this->isHtmlStringClassConst($item->value)) {
                        continue;
                    }

                    $attrName = $item->key instanceof String_ ? $item->key->value : '?';
                    $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());

                    yield new Finding(
                        checkId: $this->id(),
                        severity: $this->severity(),
                        message: "Eloquent cast for '{$attrName}' uses HtmlString::class — accessor will return unescaped HTML. Sanitize at write time, not cast time.",
                        file: $relative,
                        line: $item->getStartLine(),
                    );
                }
            }
        }
    }

    private function isHtmlStringClassConst(Node $value): bool
    {
        if (! $value instanceof ClassConstFetch) {
            return false;
        }
        if (! $value->class instanceof Name) {
            return false;
        }
        $name = ltrim($value->class->toString(), '\\');

        return $name === 'HtmlString' || $name === 'Illuminate\\Support\\HtmlString';
    }
}

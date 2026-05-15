<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Models;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use PhpParser\Node;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\Property;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class ForeignKeyFillableCheck extends AbstractCheck
{
    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'models.foreign-key-fillable';
    }

    public function category(): Category
    {
        return Category::Models;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'Foreign-key columns in $fillable allow mass-assignment of ownership';
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
        if (! is_dir($this->appPath)) {
            return;
        }

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

            /** @var array<int, Class_> $classes */
            $classes = $finder->findInstanceOf($ast, Class_::class);

            foreach ($classes as $class) {
                /** @var array<int, Property> $properties */
                $properties = $finder->find($class->stmts, function (Node $node) {
                    if (! $node instanceof Property) {
                        return false;
                    }

                    foreach ($node->props as $prop) {
                        if ($prop->name->toString() !== 'fillable') {
                            continue;
                        }

                        if ($prop->default instanceof Array_) {
                            return true;
                        }
                    }

                    return false;
                });

                foreach ($properties as $property) {
                    foreach ($property->props as $prop) {
                        if ($prop->name->toString() !== 'fillable') {
                            continue;
                        }

                        if (! $prop->default instanceof Array_) {
                            continue;
                        }

                        foreach ($prop->default->items as $item) {
                            if ($item === null) {
                                continue;
                            }

                            if (! $item->value instanceof String_) {
                                continue;
                            }

                            $column = $item->value->value;

                            if (preg_match('/^[a-z_]+_id$/i', $column) !== 1) {
                                continue;
                            }

                            $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());

                            yield new Finding(
                                checkId: $this->id(),
                                severity: $this->severity(),
                                message: "Foreign key '{$column}' in \$fillable — allows mass assignment of ownership, enabling tenant escape attacks.",
                                file: $relative,
                                line: $item->getStartLine(),
                            );
                        }
                    }
                }
            }
        }
    }
}

<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Models;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Identifier;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class ForceFillUserInputCheck extends AbstractCheck
{
    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'models.force-fill-user-input';
    }

    public function category(): Category
    {
        return Category::Models;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'forceFill() bypasses $fillable/$guarded mass-assignment protection';
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

            /** @var array<int, MethodCall> $calls */
            $calls = $finder->find($ast, function (Node $node) {
                return $node instanceof MethodCall
                    && $node->name instanceof Identifier
                    && $node->name->name === 'forceFill';
            });

            foreach ($calls as $call) {
                $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());
                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: 'forceFill() bypasses $fillable/$guarded mass-assignment protection.',
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }
        }
    }
}

<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Php;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class PhpinfoCheck extends AbstractCheck
{
    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'php.phpinfo';
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
        return 'phpinfo() calls leak environment, paths, and module configuration';
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

            /** @var array<int, FuncCall> $calls */
            $calls = $finder->find($ast, function (Node $node) {
                return $node instanceof FuncCall
                    && $node->name instanceof Name
                    && $node->name->toString() === 'phpinfo';
            });

            foreach ($calls as $call) {
                $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());
                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: 'phpinfo() leaks environment variables, loaded modules, and absolute paths — remove from production code.',
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }
        }
    }
}

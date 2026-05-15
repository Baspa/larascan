<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Injection;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use PhpParser\Node;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class ProcessShellCheck extends AbstractCheck
{
    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'injection.process-shell';
    }

    public function category(): Category
    {
        return Category::Injection;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'Process::fromShellCommandline() invokes a shell — prefer the array form';
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

            /** @var array<int, StaticCall> $calls */
            $calls = $finder->find($ast, function (Node $node): bool {
                if (! $node instanceof StaticCall) {
                    return false;
                }

                if (! $node->name instanceof Identifier || $node->name->name !== 'fromShellCommandline') {
                    return false;
                }

                if (! $node->class instanceof Name) {
                    return false;
                }

                $class = $node->class->toString();

                return $class === 'Process'
                    || $class === 'Symfony\\Component\\Process\\Process'
                    || $class === '\\Symfony\\Component\\Process\\Process';
            });

            foreach ($calls as $call) {
                $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());
                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: '`Process::fromShellCommandline()` invokes a shell which interprets metacharacters — use the `new Process([...])` array form to pass arguments safely.',
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }
        }
    }
}

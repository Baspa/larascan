<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Files;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class PathTraversalCheck extends AbstractCheck
{
    /**
     * @var array<int, string>
     */
    private const STORAGE_METHODS = ['get', 'put', 'download', 'delete', 'exists'];

    /**
     * @var array<int, string>
     */
    private const FILE_METHODS = ['get', 'put', 'delete', 'copy', 'move'];

    /**
     * @var array<int, string>
     */
    private const REQUEST_METHODS = ['input', 'query', 'get'];

    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'files.path-traversal';
    }

    public function category(): Category
    {
        return Category::Files;
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function name(): string
    {
        return 'Storage/File operation with user-controlled path — path traversal risk';
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

            /** @var array<int, StaticCall|MethodCall> $calls */
            $calls = $finder->find($ast, function (Node $node): bool {
                if (! $node instanceof StaticCall && ! $node instanceof MethodCall) {
                    return false;
                }

                if (! $node->name instanceof Identifier) {
                    return false;
                }

                $methodName = $node->name->toString();
                $className = $this->resolveClassName($node);

                if ($className === null) {
                    return false;
                }

                if ($this->isStorageClass($className) && in_array($methodName, self::STORAGE_METHODS, true)) {
                    return true;
                }

                if ($this->isFileClass($className) && in_array($methodName, self::FILE_METHODS, true)) {
                    return true;
                }

                return false;
            });

            foreach ($calls as $call) {
                if (! isset($call->args[0])) {
                    continue;
                }

                $firstArg = $call->args[0];
                if (! $firstArg instanceof Node\Arg) {
                    continue;
                }

                if (! $this->argContainsUserInput($finder, $firstArg->value)) {
                    continue;
                }

                $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());
                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: 'Storage/File operation with user-controlled path — path traversal possible. Validate against an allowlist of paths.',
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }
        }
    }

    private function resolveClassName(StaticCall|MethodCall $node): ?string
    {
        if ($node instanceof StaticCall) {
            if (! $node->class instanceof Name) {
                return null;
            }

            return $node->class->toString();
        }

        // MethodCall — check the variable name (e.g., $storage->get())
        if ($node->var instanceof Node\Expr\Variable && is_string($node->var->name)) {
            return $node->var->name;
        }

        return null;
    }

    private function isStorageClass(string $class): bool
    {
        $normalized = ltrim($class, '\\');

        return $normalized === 'Storage'
            || $normalized === 'Illuminate\\Support\\Facades\\Storage'
            || $normalized === 'storage';
    }

    private function isFileClass(string $class): bool
    {
        $normalized = ltrim($class, '\\');

        return $normalized === 'File'
            || $normalized === 'Illuminate\\Support\\Facades\\File'
            || $normalized === 'file';
    }

    private function argContainsUserInput(NodeFinder $finder, Node $node): bool
    {
        $methodMatches = $finder->find($node, function (Node $sub): bool {
            return $sub instanceof MethodCall
                && $sub->name instanceof Identifier
                && in_array($sub->name->toString(), self::REQUEST_METHODS, true);
        });

        if ($methodMatches !== []) {
            return true;
        }

        $funcMatches = $finder->find($node, function (Node $sub): bool {
            return $sub instanceof FuncCall
                && $sub->name instanceof Name
                && $sub->name->toString() === 'request';
        });

        return $funcMatches !== [];
    }
}

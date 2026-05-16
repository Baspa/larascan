<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Sql;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use PhpParser\Node;
use PhpParser\Node\Expr\ArrowFunction;
use PhpParser\Node\Expr\Closure;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor;
use PhpParser\NodeVisitorAbstract;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class OrWhereScopeBypassCheck extends AbstractCheck
{
    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'sql.orwhere-scope-bypass';
    }

    public function category(): Category
    {
        return Category::Sql;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'orWhere() chained directly after where() bypasses scoping — wrap in a closure group';
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

            $findings = $this->findInAst($ast, $file->getPathname());
            foreach ($findings as $f) {
                yield $f;
            }
        }
    }

    /**
     * @param  array<int, Node>  $ast
     * @return iterable<Finding>
     */
    private function findInAst(array $ast, string $filePath): iterable
    {
        $visitor = new class extends NodeVisitorAbstract
        {
            /** @var array<int, MethodCall> */
            public array $bypassed = [];

            public function enterNode(Node $node): ?int
            {
                if ($node instanceof Closure || $node instanceof ArrowFunction) {
                    return NodeVisitor::DONT_TRAVERSE_CHILDREN;
                }

                if (
                    $node instanceof MethodCall
                    && $node->name instanceof Identifier
                    && $node->name->toString() === 'orWhere'
                    && $this->precedingCallIsWhere($node->var)
                ) {
                    $this->bypassed[] = $node;
                }

                return null;
            }

            private function precedingCallIsWhere(Node $var): bool
            {
                $name = null;

                if ($var instanceof MethodCall && $var->name instanceof Identifier) {
                    $name = $var->name->toString();
                } elseif ($var instanceof StaticCall && $var->name instanceof Identifier) {
                    $name = $var->name->toString();
                }

                return $name !== null && $name === 'where';
            }
        };

        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $filePath);

        foreach ($visitor->bypassed as $call) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: 'orWhere() chained directly after where() — wrap in ->where(function ($q) { $q->where(...)->orWhere(...); }) to scope it correctly.',
                file: $relative,
                line: $call->getStartLine(),
            );
        }
    }
}

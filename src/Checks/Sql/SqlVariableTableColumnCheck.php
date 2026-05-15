<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Sql;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class SqlVariableTableColumnCheck extends AbstractCheck
{
    /**
     * @var array<int, string>
     */
    private const DB_CLASS_NAMES = ['DB', '\Illuminate\Support\Facades\DB', 'Illuminate\Support\Facades\DB'];

    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'sql.variable-table-column';
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
        return 'Variable table or column name in DB::table()/->from()/->select() — validate against an allowlist';
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

            $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());

            /** @var array<int, StaticCall> $dbTableCalls */
            $dbTableCalls = $finder->find($ast, function (Node $node): bool {
                return $node instanceof StaticCall
                    && $node->class instanceof Name
                    && in_array($node->class->toString(), self::DB_CLASS_NAMES, true)
                    && $node->name instanceof Identifier
                    && $node->name->toString() === 'table';
            });

            foreach ($dbTableCalls as $call) {
                if (! $this->firstArgIsVariable($call)) {
                    continue;
                }

                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: 'Variable DB::table() argument — variable table/column name. Validate against an allowlist before passing.',
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }

            /** @var array<int, MethodCall> $fromCalls */
            $fromCalls = $finder->find($ast, function (Node $node): bool {
                return $node instanceof MethodCall
                    && $node->name instanceof Identifier
                    && $node->name->toString() === 'from';
            });

            foreach ($fromCalls as $call) {
                if (! $this->firstArgIsVariable($call)) {
                    continue;
                }

                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: 'Variable ->from() argument — variable table/column name. Validate against an allowlist before passing.',
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }

            /** @var array<int, MethodCall> $selectCalls */
            $selectCalls = $finder->find($ast, function (Node $node): bool {
                return $node instanceof MethodCall
                    && $node->name instanceof Identifier
                    && $node->name->toString() === 'select';
            });

            foreach ($selectCalls as $call) {
                if (! $this->anyArgIsVariable($call)) {
                    continue;
                }

                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: 'Variable ->select() argument — variable table/column name. Validate against an allowlist before passing.',
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }
        }
    }

    /**
     * @param  StaticCall|MethodCall  $call
     */
    private function firstArgIsVariable(Node $call): bool
    {
        if (! isset($call->args[0]) || ! $call->args[0] instanceof Node\Arg) {
            return false;
        }

        return $call->args[0]->value instanceof Variable;
    }

    /**
     * @param  StaticCall|MethodCall  $call
     */
    private function anyArgIsVariable(Node $call): bool
    {
        foreach ($call->args as $arg) {
            if (! $arg instanceof Node\Arg) {
                continue;
            }

            if ($arg->value instanceof Variable) {
                return true;
            }
        }

        return false;
    }
}

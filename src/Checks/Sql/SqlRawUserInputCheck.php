<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Sql;

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

final class SqlRawUserInputCheck extends AbstractCheck
{
    /**
     * @var array<int, string>
     */
    private const REQUEST_METHODS = ['input', 'query', 'get', 'header'];

    /**
     * @var array<int, string>
     */
    private const RAW_METHOD_CALLS = ['whereRaw', 'selectRaw', 'havingRaw', 'groupByRaw'];

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
        return 'sql.raw-user-input';
    }

    public function category(): Category
    {
        return Category::Sql;
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function name(): string
    {
        return 'Raw SQL (DB::raw / whereRaw / selectRaw) with user-input argument — SQL injection risk';
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

            /** @var array<int, StaticCall> $staticCalls */
            $staticCalls = $finder->find($ast, function (Node $node): bool {
                return $node instanceof StaticCall
                    && $node->class instanceof Name
                    && in_array($node->class->toString(), self::DB_CLASS_NAMES, true)
                    && $node->name instanceof Identifier
                    && $node->name->toString() === 'raw';
            });

            foreach ($staticCalls as $call) {
                if (! $this->callArgsContainUserInput($finder, $call)) {
                    continue;
                }

                $methodName = 'DB::raw';
                $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());
                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: "Raw SQL '{$methodName}' with user-input argument — SQL injection risk. Use parameter bindings: ->whereRaw('col = ?', [\$value]).",
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }

            /** @var array<int, MethodCall> $methodCalls */
            $methodCalls = $finder->find($ast, function (Node $node): bool {
                return $node instanceof MethodCall
                    && $node->name instanceof Identifier
                    && in_array($node->name->toString(), self::RAW_METHOD_CALLS, true);
            });

            foreach ($methodCalls as $call) {
                if (! $this->callArgsContainUserInput($finder, $call)) {
                    continue;
                }

                /** @var Identifier $nameNode */
                $nameNode = $call->name;
                $methodName = $nameNode->toString();
                $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());
                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: "Raw SQL '{$methodName}' with user-input argument — SQL injection risk. Use parameter bindings: ->whereRaw('col = ?', [\$value]).",
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }
        }
    }

    /**
     * @param  StaticCall|MethodCall  $call
     */
    private function callArgsContainUserInput(NodeFinder $finder, Node $call): bool
    {
        foreach ($call->args as $arg) {
            if (! $arg instanceof Node\Arg) {
                continue;
            }

            if ($this->argContainsUserInput($finder, $arg->value)) {
                return true;
            }
        }

        return false;
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

        if ($node instanceof MethodCall
            && $node->name instanceof Identifier
            && in_array($node->name->toString(), self::REQUEST_METHODS, true)) {
            return true;
        }

        $funcMatches = $finder->find($node, function (Node $sub): bool {
            return $sub instanceof FuncCall
                && $sub->name instanceof Name
                && $sub->name->toString() === 'request';
        });

        if ($funcMatches !== []) {
            return true;
        }

        if ($node instanceof FuncCall
            && $node->name instanceof Name
            && $node->name->toString() === 'request') {
            return true;
        }

        return false;
    }
}

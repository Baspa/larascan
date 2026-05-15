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
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class SqlRawOrderByCheck extends AbstractCheck
{
    /**
     * @var array<int, string>
     */
    private const REQUEST_METHODS = ['input', 'query', 'get', 'header'];

    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'sql.raw-order-by';
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
        return 'orderByRaw with user-input argument — SQL injection in ORDER BY clause';
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

            /** @var array<int, MethodCall> $methodCalls */
            $methodCalls = $finder->find($ast, function (Node $node): bool {
                return $node instanceof MethodCall
                    && $node->name instanceof Identifier
                    && $node->name->toString() === 'orderByRaw';
            });

            foreach ($methodCalls as $call) {
                if (! $this->callArgsContainUserInput($finder, $call)) {
                    continue;
                }

                $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());
                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: 'orderByRaw with user input — SQL injection in ORDER BY clause. Validate sort column against an allowlist.',
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }
        }
    }

    private function callArgsContainUserInput(NodeFinder $finder, MethodCall $call): bool
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

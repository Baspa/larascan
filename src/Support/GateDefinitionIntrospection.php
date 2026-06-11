<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

use PhpParser\Node;
use PhpParser\Node\Expr\ArrowFunction;
use PhpParser\Node\Expr\Closure;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Return_;
use PhpParser\NodeFinder;

/**
 * Finds `Gate::define('<gate>', <closure>)` calls whose closure is trivially
 * true — i.e. `function (...) { return true; }` or `fn (...) => true`.
 *
 * Only trivially-true closures are judged: a gate body with any real logic
 * (user checks, environment branches, etc.) is never reported, even when it
 * might effectively always allow access.
 */
final class GateDefinitionIntrospection
{
    public function __construct(
        private readonly FileParser $parser,
    ) {}

    /**
     * Scan the given provider files for a trivially-true definition of the
     * named gate. Returns the first match, or null when none is found.
     *
     * @param  array<int, string>  $providerFiles  absolute paths
     * @return array{file: string, line: int}|null
     */
    public function findTriviallyTrueGate(array $providerFiles, string $gateName): ?array
    {
        $finder = new NodeFinder;

        foreach ($providerFiles as $file) {
            if (! is_file($file)) {
                continue;
            }

            $ast = $this->parser->parse($file);
            if ($ast === null) {
                continue;
            }

            /** @var array<int, StaticCall> $calls */
            $calls = $finder->find($ast, function (Node $node) use ($gateName): bool {
                return $node instanceof StaticCall
                    && $this->isGateDefineCall($node, $gateName);
            });

            foreach ($calls as $call) {
                $callback = $call->getArgs()[1]->value ?? null;
                if ($callback !== null && $this->isTriviallyTrue($callback)) {
                    return ['file' => $file, 'line' => $call->getStartLine()];
                }
            }
        }

        return null;
    }

    /**
     * Note: only literal `Gate` / FQCN class names are matched — aliased
     * imports (`use Illuminate\Support\Facades\Gate as G`) are not resolved.
     */
    private function isGateDefineCall(StaticCall $call, string $gateName): bool
    {
        if (! $call->class instanceof Name) {
            return false;
        }

        $fqcn = ltrim($call->class->toString(), '\\');
        if ($fqcn !== 'Gate' && $fqcn !== 'Illuminate\\Support\\Facades\\Gate') {
            return false;
        }

        if (! $call->name instanceof Identifier || $call->name->toString() !== 'define') {
            return false;
        }

        $nameArg = $call->getArgs()[0]->value ?? null;

        return $nameArg instanceof String_ && $nameArg->value === $gateName;
    }

    private function isTriviallyTrue(Node $callback): bool
    {
        if ($callback instanceof ArrowFunction) {
            return $this->isTrueConst($callback->expr);
        }

        if ($callback instanceof Closure) {
            return count($callback->stmts) === 1
                && $callback->stmts[0] instanceof Return_
                && $callback->stmts[0]->expr !== null
                && $this->isTrueConst($callback->stmts[0]->expr);
        }

        return false;
    }

    private function isTrueConst(Node $expr): bool
    {
        return $expr instanceof ConstFetch
            && strtolower($expr->name->toString()) === 'true';
    }
}

<?php

declare(strict_types=1);

namespace Baspa\Larascan\Advices\Routing;

use Baspa\Larascan\Support\AbstractAdvice;
use Baspa\Larascan\Support\AdviceEvidence;
use Baspa\Larascan\Support\AdviceOutcome;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use PhpParser\Node;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PhpParser\NodeFinder;

final class BroadcastChannelsFlagsAdvice extends AbstractAdvice
{
    public function __construct(
        private readonly string $basePath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'advise.broadcast-channels-flags';
    }

    public function category(): Category
    {
        return Category::Routing;
    }

    public function name(): string
    {
        return 'Broadcast channels exist — review their authorization flags by hand';
    }

    public function isApplicable(): bool
    {
        return true;
    }

    public function run(): AdviceOutcome
    {
        $path = $this->basePath.'/routes/channels.php';

        if (! is_file($path)) {
            return AdviceOutcome::skipped('routes/channels.php not present');
        }

        $ast = $this->parser->parse($path);
        if ($ast === null) {
            return AdviceOutcome::skipped('could not parse routes/channels.php');
        }

        $finder = new NodeFinder;
        /** @var array<int, StaticCall> $calls */
        $calls = $finder->find($ast, function (Node $node): bool {
            if (! $node instanceof StaticCall) {
                return false;
            }
            if (! $node->class instanceof Name) {
                return false;
            }
            $fqcn = ltrim($node->class->toString(), '\\');
            if ($fqcn !== 'Broadcast' && $fqcn !== 'Illuminate\\Support\\Facades\\Broadcast') {
                return false;
            }

            return $node->name instanceof Identifier && $node->name->toString() === 'channel';
        });

        $evidence = [];
        foreach ($calls as $call) {
            $nameArg = $call->getArgs()[0]->value ?? null;
            $channelName = $nameArg instanceof String_ ? $nameArg->value : '(dynamic)';
            $evidence[] = new AdviceEvidence(
                message: "channel '{$channelName}' — review its callback for authorization checks (Gate::, ->can(), is_active, etc.)",
                file: 'routes/channels.php',
                line: $call->getStartLine(),
            );
        }

        if ($evidence === []) {
            return AdviceOutcome::notSurfaced();
        }

        return AdviceOutcome::surfaced(
            sprintf('%d broadcast channel(s) found — review their authorization callbacks.', count($evidence)),
            $evidence,
        );
    }
}

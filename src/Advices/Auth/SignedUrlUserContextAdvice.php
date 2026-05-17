<?php

declare(strict_types=1);

namespace Baspa\Larascan\Advices\Auth;

use Baspa\Larascan\Support\AbstractAdvice;
use Baspa\Larascan\Support\AdviceEvidence;
use Baspa\Larascan\Support\AdviceOutcome;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use PhpParser\Node;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ArrayItem;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class SignedUrlUserContextAdvice extends AbstractAdvice
{
    private const USER_BOUND_KEY = '~^(user|user_?id|user_?uuid|email|account|member|owner|uuid)$~i';

    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'advise.signed-url-user-context';
    }

    public function category(): Category
    {
        return Category::Auth;
    }

    public function name(): string
    {
        return 'Signed URLs should include user-bound parameters so a leaked link is tied to a specific user';
    }

    public function isApplicable(): bool
    {
        return is_dir($this->appPath);
    }

    public function run(): AdviceOutcome
    {
        $finder = new NodeFinder;
        $evidence = [];

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
                if (! $node->class instanceof Name) {
                    return false;
                }
                $classFqcn = ltrim($node->class->toString(), '\\');
                if ($classFqcn !== 'URL' && $classFqcn !== 'Illuminate\\Support\\Facades\\URL') {
                    return false;
                }
                if (! $node->name instanceof Identifier) {
                    return false;
                }

                return in_array($node->name->toString(), ['signedRoute', 'temporarySignedRoute'], true);
            });

            foreach ($calls as $call) {
                $methodName = $call->name instanceof Identifier ? $call->name->toString() : 'signedRoute';
                $paramsIndex = $methodName === 'signedRoute' ? 1 : 2;
                $args = $call->getArgs();
                $paramsArg = $args[$paramsIndex] ?? null;

                if ($paramsArg === null) {
                    continue;
                }

                $value = $paramsArg->value;
                if (! $value instanceof Array_) {
                    continue;
                }

                if ($value->items === []) {
                    continue;
                }

                if ($this->arrayHasUserBoundKey($value)) {
                    continue;
                }

                $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());

                $evidence[] = new AdviceEvidence(
                    message: "{$methodName}() with params but no user-bound key",
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }
        }

        if ($evidence === []) {
            return AdviceOutcome::notSurfaced();
        }

        $count = count($evidence);

        return AdviceOutcome::surfaced(
            "{$count} signed URL call(s) have params but no user-bound key (user, user_id, email, uuid, etc.).",
            $evidence,
        );
    }

    private function arrayHasUserBoundKey(Array_ $array): bool
    {
        foreach ($array->items as $item) {
            if (! $item instanceof ArrayItem) {
                continue;
            }
            if (! $item->key instanceof String_) {
                continue;
            }
            if (preg_match(self::USER_BOUND_KEY, $item->key->value) === 1) {
                return true;
            }
        }

        return false;
    }
}

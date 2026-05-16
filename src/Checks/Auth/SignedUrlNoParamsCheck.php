<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Auth;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use PhpParser\Node;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class SignedUrlNoParamsCheck extends AbstractCheck
{
    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'auth.signed-url-no-params';
    }

    public function category(): Category
    {
        return Category::Auth;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'Signed URLs must include user-bound params so a leaked link is not usable by anyone';
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
                $hasParams = false;

                if ($paramsArg !== null) {
                    $value = $paramsArg->value;
                    if (! $value instanceof Array_) {
                        $hasParams = true;
                    } else {
                        $hasParams = $value->items !== [];
                    }
                }

                if ($hasParams) {
                    continue;
                }

                $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());

                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: "{$methodName}() called without route parameters — anyone with the link can use it. Add a user-bound param like ['user' => \$user->id].",
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }
        }
    }
}

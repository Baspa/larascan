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
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Identifier;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class ApiAbilityScopingCheck extends AbstractCheck
{
    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'auth.api-ability-scoping';
    }

    public function category(): Category
    {
        return Category::Auth;
    }

    public function severity(): Severity
    {
        return Severity::Low;
    }

    public function name(): string
    {
        return 'Sanctum createToken() calls should pass a non-empty abilities array to scope token permissions';
    }

    public function isApplicable(): bool
    {
        return class_exists('Laravel\\Sanctum\\Sanctum') && is_dir($this->appPath);
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

            /** @var array<int, MethodCall> $calls */
            $calls = $finder->find($ast, function (Node $node): bool {
                return $node instanceof MethodCall
                    && $node->name instanceof Identifier
                    && $node->name->name === 'createToken';
            });

            foreach ($calls as $call) {
                $args = $call->getArgs();

                $secondArg = $args[1] ?? null;

                $isUnscoped = false;

                if ($secondArg === null) {
                    $isUnscoped = true;
                } else {
                    $value = $secondArg->value;

                    if ($value instanceof ConstFetch
                        && strtolower($value->name->toString()) === 'null'
                    ) {
                        $isUnscoped = true;
                    } elseif ($value instanceof Array_ && count($value->items) === 0) {
                        $isUnscoped = true;
                    }
                }

                if (! $isUnscoped) {
                    continue;
                }

                $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());

                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: "createToken() in {$relative}:{$call->getStartLine()} creates a token without scoped abilities — token can perform any action. Pass specific abilities array.",
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }
        }
    }
}

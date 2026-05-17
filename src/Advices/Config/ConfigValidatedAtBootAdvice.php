<?php

declare(strict_types=1);

namespace Baspa\Larascan\Advices\Config;

use Baspa\Larascan\Support\AbstractAdvice;
use Baspa\Larascan\Support\AdviceEvidence;
use Baspa\Larascan\Support\AdviceOutcome;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Throw_ as ThrowExpr;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class ConfigValidatedAtBootAdvice extends AbstractAdvice
{
    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'advise.config-validated-at-boot';
    }

    public function category(): Category
    {
        return Category::Config;
    }

    public function name(): string
    {
        return 'Validate critical config at boot — throw if a required value is missing';
    }

    public function run(): AdviceOutcome
    {
        $providersDir = $this->appPath.'/Providers';
        if (! is_dir($providersDir)) {
            return AdviceOutcome::skipped('app/Providers/ not present');
        }

        $finder = new NodeFinder;
        $foundValidation = false;

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($providersDir, RecursiveDirectoryIterator::SKIP_DOTS),
        );

        foreach ($iterator as $file) {
            if (! $file instanceof SplFileInfo || ! $file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }

            $ast = $this->parser->parse($file->getPathname());
            if ($ast === null) {
                continue;
            }

            /** @var array<int, ClassMethod> $methods */
            $methods = $finder->findInstanceOf($ast, ClassMethod::class);
            foreach ($methods as $method) {
                if (! $this->methodHasThrowWithConfig($method, $finder)) {
                    continue;
                }
                $foundValidation = true;
                break 2;
            }
        }

        if ($foundValidation) {
            return AdviceOutcome::notSurfaced();
        }

        return AdviceOutcome::surfaced(
            'No service provider was found that throws on missing config — consider adding boot-time config validation.',
            [new AdviceEvidence(message: 'Inspect app/Providers/AppServiceProvider.php (or similar) for missing-config guards.')],
        );
    }

    private function methodHasThrowWithConfig(ClassMethod $method, NodeFinder $finder): bool
    {
        $stmts = $method->stmts ?? [];
        if ($stmts === []) {
            return false;
        }

        $throws = $finder->find($stmts, fn (Node $node): bool => $node instanceof ThrowExpr);
        if ($throws === []) {
            return false;
        }

        $configMatches = $finder->find($stmts, function (Node $node): bool {
            if ($node instanceof FuncCall && $node->name instanceof Name && ltrim($node->name->toString(), '\\') === 'config') {
                return true;
            }
            if (
                $node instanceof StaticCall
                && $node->class instanceof Name
                && in_array(ltrim($node->class->toString(), '\\'), ['Config', 'Illuminate\\Support\\Facades\\Config'], true)
                && $node->name instanceof Identifier
                && in_array($node->name->toString(), ['get', 'has'], true)
            ) {
                return true;
            }

            return false;
        });

        return $configMatches !== [];
    }
}

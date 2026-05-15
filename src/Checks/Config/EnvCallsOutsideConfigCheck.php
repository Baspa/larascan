<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Config;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class EnvCallsOutsideConfigCheck extends AbstractCheck
{
    public function __construct(
        private readonly string $basePath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'config.env-calls-outside-config';
    }

    public function category(): Category
    {
        return Category::Config;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'env() calls outside config/ defeat config caching';
    }

    public function isApplicable(): bool
    {
        return is_dir($this->basePath.'/app');
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        $finder = new NodeFinder;

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->basePath.'/app', RecursiveDirectoryIterator::SKIP_DOTS),
        );

        foreach ($iterator as $file) {
            if (! $file instanceof SplFileInfo || ! $file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }

            $ast = $this->parser->parse($file->getPathname());
            if ($ast === null) {
                continue;
            }

            /** @var array<int, FuncCall> $calls */
            $calls = $finder->find($ast, function (Node $node) {
                return $node instanceof FuncCall
                    && $node->name instanceof Name
                    && $node->name->toString() === 'env';
            });

            foreach ($calls as $call) {
                $relative = str_replace($this->basePath.'/', '', $file->getPathname());
                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: 'env() called outside config/ — move to a config file so config caching keeps working.',
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }
        }
    }
}

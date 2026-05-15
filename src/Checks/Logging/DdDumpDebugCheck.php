<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Logging;

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

final class DdDumpDebugCheck extends AbstractCheck
{
    /**
     * @var array<int, string>
     */
    private const DEBUG_FUNCTIONS = ['dd', 'dump', 'var_dump'];

    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'logging.dd-dump-debug';
    }

    public function category(): Category
    {
        return Category::Logging;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'dd()/dump()/var_dump() left in application code';
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

            /** @var array<int, FuncCall> $calls */
            $calls = $finder->find($ast, function (Node $node) {
                return $node instanceof FuncCall
                    && $node->name instanceof Name
                    && in_array($node->name->toString(), self::DEBUG_FUNCTIONS, true);
            });

            foreach ($calls as $call) {
                /** @var Name $name */
                $name = $call->name;
                $funcName = $name->toString();
                $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());
                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: "{$funcName}() left in application code — debugging helper in production can leak data and crash responses.",
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }
        }
    }
}

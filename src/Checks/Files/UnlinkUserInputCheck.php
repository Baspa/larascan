<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Files;

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

final class UnlinkUserInputCheck extends AbstractCheck
{
    /**
     * @var array<int, string>
     */
    private const FUNCTIONS = ['unlink', 'rmdir'];

    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'files.unlink-user-input';
    }

    public function category(): Category
    {
        return Category::Files;
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function name(): string
    {
        return 'unlink()/rmdir() deletes filesystem entries — verify path is not user-controlled';
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
            $calls = $finder->find($ast, function (Node $node): bool {
                if (! $node instanceof FuncCall || ! $node->name instanceof Name) {
                    return false;
                }

                return in_array($node->name->toString(), self::FUNCTIONS, true);
            });

            foreach ($calls as $call) {
                /** @var Name $nameNode */
                $nameNode = $call->name;
                $funcName = $nameNode->toString();

                $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());
                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: "`{$funcName}()` deletes filesystem entries — verify path is not user-controlled.",
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }
        }
    }
}

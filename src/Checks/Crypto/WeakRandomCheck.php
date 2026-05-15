<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Crypto;

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

final class WeakRandomCheck extends AbstractCheck
{
    /**
     * @var array<int, string>
     */
    private const WEAK_RANDOM_FUNCTIONS = ['rand', 'mt_rand', 'uniqid'];

    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'crypto.weak-random';
    }

    public function category(): Category
    {
        return Category::Crypto;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'Weak random function used for security-sensitive values';
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
                return $node instanceof FuncCall
                    && $node->name instanceof Name
                    && in_array($node->name->toString(), self::WEAK_RANDOM_FUNCTIONS, true);
            });

            foreach ($calls as $call) {
                /** @var Name $nameNode */
                $nameNode = $call->name;
                $funcName = $nameNode->toString();
                $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());
                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: "Weak random function '{$funcName}' — not cryptographically secure. Use random_bytes(), random_int(), or Str::random() for security-sensitive tokens.",
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }
        }
    }
}

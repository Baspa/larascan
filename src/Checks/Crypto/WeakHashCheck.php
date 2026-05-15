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
use PhpParser\Node\Scalar\String_;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class WeakHashCheck extends AbstractCheck
{
    /**
     * @var array<int, string>
     */
    private const DIRECT_WEAK_HASHES = ['md5', 'sha1'];

    /**
     * @var array<int, string>
     */
    private const WEAK_HASH_ALGOS = ['md5', 'sha1', 'md4'];

    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'crypto.weak-hash';
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
        return 'Weak hash function (md5/sha1/md4) used';
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

                $name = $node->name->toString();

                if (in_array($name, self::DIRECT_WEAK_HASHES, true)) {
                    return true;
                }

                if ($name === 'hash') {
                    $firstArg = $node->args[0] ?? null;
                    if ($firstArg instanceof Node\Arg && $firstArg->value instanceof String_) {
                        return in_array(strtolower($firstArg->value->value), self::WEAK_HASH_ALGOS, true);
                    }
                }

                return false;
            });

            foreach ($calls as $call) {
                /** @var Name $nameNode */
                $nameNode = $call->name;
                $funcName = $nameNode->toString();

                if ($funcName === 'hash') {
                    $firstArg = $call->args[0] ?? null;
                    if ($firstArg instanceof Node\Arg && $firstArg->value instanceof String_) {
                        $reported = "hash('".strtolower($firstArg->value->value)."', ...)";
                    } else {
                        $reported = 'hash';
                    }
                } else {
                    $reported = $funcName;
                }

                $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());
                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: "Weak hash function '{$reported}' — md5/sha1 are broken for security purposes. Use password_hash() / Hash::make() / hash('sha256', ...).",
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }
        }
    }
}

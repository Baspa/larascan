<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Crypto;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use PhpParser\Node;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Function_;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class PasswordSelfGeneratedCheck extends AbstractCheck
{
    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'crypto.password-self-generated';
    }

    public function category(): Category
    {
        return Category::Crypto;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'App-generated passwords must use Str::password(), not random/hash helpers';
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

            /** @var array<int, ClassMethod|Function_> $methods */
            $methods = $finder->find($ast, fn (Node $n): bool => $n instanceof ClassMethod || $n instanceof Function_);

            foreach ($methods as $method) {
                $stmts = $method->stmts ?? [];
                $count = count($stmts);
                for ($i = 0; $i < $count; $i++) {
                    if (! $this->statementContainsWeakGenerator($finder, $stmts[$i])) {
                        continue;
                    }

                    $window = array_slice($stmts, max(0, $i - 3), min($count, $i + 4) - max(0, $i - 3));
                    if (! $this->windowMentionsPassword($finder, $window)) {
                        continue;
                    }

                    $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());

                    yield new Finding(
                        checkId: $this->id(),
                        severity: $this->severity(),
                        message: 'Weak generator (Str::random/md5/sha1/uniqid/random_bytes/bin2hex) used near a password symbol — use Str::password() for app-generated passwords.',
                        file: $relative,
                        line: $stmts[$i]->getStartLine(),
                    );

                    // One finding per method to avoid noise.
                    break;
                }
            }
        }
    }

    private function statementContainsWeakGenerator(NodeFinder $finder, Node $stmt): bool
    {
        $matches = $finder->find([$stmt], function (Node $node): bool {
            if ($node instanceof Node\Expr\StaticCall
                && $node->class instanceof Node\Name
                && ltrim($node->class->toString(), '\\') === 'Str'
                && $node->name instanceof Node\Identifier
                && $node->name->toString() === 'random'
            ) {
                return true;
            }
            if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
                return in_array(ltrim($node->name->toString(), '\\'), ['md5', 'sha1', 'uniqid', 'random_bytes', 'bin2hex'], true);
            }

            return false;
        });

        return $matches !== [];
    }

    /**
     * @param  array<int, Node>  $stmts
     */
    private function windowMentionsPassword(NodeFinder $finder, array $stmts): bool
    {
        $matches = $finder->find($stmts, function (Node $node): bool {
            if ($node instanceof Node\Expr\Variable && is_string($node->name) && stripos($node->name, 'password') !== false) {
                return true;
            }
            if ($node instanceof Node\Identifier && stripos($node->toString(), 'password') !== false) {
                return true;
            }
            if ($node instanceof Node\Scalar\String_ && stripos($node->value, 'password') !== false) {
                return true;
            }

            return false;
        });

        return $matches !== [];
    }
}

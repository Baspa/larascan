<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Injection;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class OpenRedirectCheck extends AbstractCheck
{
    /**
     * @var array<int, string>
     */
    private const REQUEST_METHODS = ['input', 'query', 'get', 'header'];

    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'injection.open-redirect';
    }

    public function category(): Category
    {
        return Category::Injection;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'redirect() with user-controlled URL is an open-redirect risk';
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

            /** @var array<int, FuncCall> $redirects */
            $redirects = $finder->find($ast, function (Node $node): bool {
                return $node instanceof FuncCall
                    && $node->name instanceof Name
                    && $node->name->toString() === 'redirect';
            });

            foreach ($redirects as $redirect) {
                if (! isset($redirect->args[0])) {
                    continue;
                }

                $firstArg = $redirect->args[0];
                if (! $firstArg instanceof Node\Arg) {
                    continue;
                }

                if (! $this->argContainsUserInput($finder, $firstArg->value)) {
                    continue;
                }

                $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());
                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: 'redirect() with user-controlled URL — open redirect risk. Allowlist target URLs or use signed routes.',
                    file: $relative,
                    line: $redirect->getStartLine(),
                );
            }
        }
    }

    private function argContainsUserInput(NodeFinder $finder, Node $node): bool
    {
        $methodMatches = $finder->find($node, function (Node $sub): bool {
            return $sub instanceof MethodCall
                && $sub->name instanceof Identifier
                && in_array($sub->name->toString(), self::REQUEST_METHODS, true);
        });

        if ($methodMatches !== []) {
            return true;
        }

        $funcMatches = $finder->find($node, function (Node $sub): bool {
            return $sub instanceof FuncCall
                && $sub->name instanceof Name
                && $sub->name->toString() === 'request';
        });

        return $funcMatches !== [];
    }
}

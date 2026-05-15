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
use PhpParser\Node\Name;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class CommandInjectionCheck extends AbstractCheck
{
    /**
     * @var array<int, string>
     */
    private const COMMAND_FUNCTIONS = [
        'exec',
        'shell_exec',
        'system',
        'passthru',
        'popen',
        'proc_open',
    ];

    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'injection.command';
    }

    public function category(): Category
    {
        return Category::Injection;
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function name(): string
    {
        return 'Command execution via exec/shell_exec/system/passthru/popen/proc_open';
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

                return in_array($node->name->toString(), self::COMMAND_FUNCTIONS, true);
            });

            foreach ($calls as $call) {
                /** @var Name $nameNode */
                $nameNode = $call->name;
                $funcName = $nameNode->toString();

                $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());
                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: "Command execution via '{$funcName}()' — vulnerable to command injection if any argument comes from user input. Use Symfony Process with array-form arguments instead.",
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }
        }
    }
}

<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Logging;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use PhpParser\Node;
use PhpParser\Node\ArrayItem;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class SensitiveInLogContextCheck extends AbstractCheck
{
    /**
     * @var array<int, string>
     */
    private const LOG_METHODS = [
        'debug',
        'info',
        'notice',
        'warning',
        'error',
        'critical',
        'alert',
        'emergency',
    ];

    /**
     * @var array<int, string>
     */
    private const SENSITIVE_KEYS = [
        'password',
        'token',
        'secret',
        'api_key',
        'apikey',
    ];

    /**
     * @var array<int, string>
     */
    private const LOG_CLASS_NAMES = [
        'Log',
        'Illuminate\\Support\\Facades\\Log',
    ];

    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'logging.sensitive-in-log-context';
    }

    public function category(): Category
    {
        return Category::Logging;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'Sensitive keys (password, token, secret, api_key) passed to Log::*() context';
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

            /** @var array<int, StaticCall|MethodCall> $calls */
            $calls = $finder->find($ast, function (Node $node): bool {
                return $this->isLogCall($node);
            });

            foreach ($calls as $call) {
                $args = $call->getArgs();
                if (count($args) < 2) {
                    continue;
                }

                $contextArg = $args[1]->value;
                if (! $contextArg instanceof Array_) {
                    continue;
                }

                $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());

                foreach ($contextArg->items as $item) {
                    if (! $item instanceof ArrayItem || $item->key === null) {
                        continue;
                    }

                    if (! $item->key instanceof String_) {
                        continue;
                    }

                    $keyName = strtolower($item->key->value);
                    if (! in_array($keyName, self::SENSITIVE_KEYS, true)) {
                        continue;
                    }

                    yield new Finding(
                        checkId: $this->id(),
                        severity: $this->severity(),
                        message: "Log context contains sensitive key '{$item->key->value}' — log files will store the raw value.",
                        file: $relative,
                        line: $call->getStartLine(),
                    );
                }
            }
        }
    }

    private function isLogCall(Node $node): bool
    {
        if ($node instanceof StaticCall) {
            if (! $node->name instanceof Identifier) {
                return false;
            }
            if (! in_array($node->name->name, self::LOG_METHODS, true)) {
                return false;
            }
            if (! $node->class instanceof Name) {
                return false;
            }

            return in_array(ltrim($node->class->toString(), '\\'), self::LOG_CLASS_NAMES, true);
        }

        if ($node instanceof MethodCall) {
            if (! $node->name instanceof Identifier) {
                return false;
            }
            if (! in_array($node->name->name, self::LOG_METHODS, true)) {
                return false;
            }

            // Heuristic: accept `$log->info(...)` or `Log::channel(...)->info(...)`
            // chains where the receiver variable is named "log".
            if ($node->var instanceof Variable && is_string($node->var->name)) {
                return strtolower($node->var->name) === 'log';
            }

            return false;
        }

        return false;
    }
}

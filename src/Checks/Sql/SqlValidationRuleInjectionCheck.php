<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Sql;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class SqlValidationRuleInjectionCheck extends AbstractCheck
{
    /**
     * @var array<int, string>
     */
    private const VALIDATOR_CLASS_NAMES = [
        'Validator',
        '\Illuminate\Support\Facades\Validator',
        'Illuminate\Support\Facades\Validator',
    ];

    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'sql.validation-rule-injection';
    }

    public function category(): Category
    {
        return Category::Sql;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'Validation rules sourced from a variable — risk of validation bypass or SQL injection via exists/unique rule';
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

            $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());

            /** @var array<int, MethodCall> $validateCalls */
            $validateCalls = $finder->find($ast, function (Node $node): bool {
                return $node instanceof MethodCall
                    && $node->name instanceof Identifier
                    && $node->name->toString() === 'validate';
            });

            foreach ($validateCalls as $call) {
                if (! $this->argAtIsVariable($call, 1)) {
                    continue;
                }

                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: "Validation rules sourced from a variable — if rules come from user input, attackers can bypass validation or inject SQL via 'exists:table' rule. Use a literal array.",
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }

            /** @var array<int, StaticCall> $validatorMakeCalls */
            $validatorMakeCalls = $finder->find($ast, function (Node $node): bool {
                return $node instanceof StaticCall
                    && $node->class instanceof Name
                    && in_array($node->class->toString(), self::VALIDATOR_CLASS_NAMES, true)
                    && $node->name instanceof Identifier
                    && $node->name->toString() === 'make';
            });

            foreach ($validatorMakeCalls as $call) {
                if (! $this->argAtIsVariable($call, 1)) {
                    continue;
                }

                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: "Validation rules sourced from a variable — if rules come from user input, attackers can bypass validation or inject SQL via 'exists:table' rule. Use a literal array.",
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }

            /** @var array<int, FuncCall> $validatorFuncCalls */
            $validatorFuncCalls = $finder->find($ast, function (Node $node): bool {
                return $node instanceof FuncCall
                    && $node->name instanceof Name
                    && $node->name->toString() === 'validator';
            });

            foreach ($validatorFuncCalls as $call) {
                if (! $this->argAtIsVariable($call, 1)) {
                    continue;
                }

                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: "Validation rules sourced from a variable — if rules come from user input, attackers can bypass validation or inject SQL via 'exists:table' rule. Use a literal array.",
                    file: $relative,
                    line: $call->getStartLine(),
                );
            }
        }
    }

    /**
     * @param  StaticCall|MethodCall|FuncCall  $call
     */
    private function argAtIsVariable(Node $call, int $index): bool
    {
        if (! isset($call->args[$index]) || ! $call->args[$index] instanceof Node\Arg) {
            return false;
        }

        return $call->args[$index]->value instanceof Variable;
    }
}

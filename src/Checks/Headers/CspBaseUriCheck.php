<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Headers;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use PhpParser\Node;
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PhpParser\NodeFinder;
use ReflectionClass;
use Throwable;

final class CspBaseUriCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'headers.csp-base-uri';
    }

    public function category(): Category
    {
        return Category::Headers;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'CSP policy must include a base-uri directive to prevent <base> tag injection';
    }

    public function isApplicable(): bool
    {
        return class_exists('Spatie\\Csp\\AddCspHeaders');
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        if (! $this->isApplicable()) {
            return;
        }

        /** @var Repository $config */
        $config = $this->app->make('config');
        $policyClass = $config->get('csp.policy');

        if (! is_string($policyClass) || $policyClass === '' || ! class_exists($policyClass)) {
            return;
        }

        try {
            $reflection = new ReflectionClass($policyClass);
            $file = $reflection->getFileName();
        } catch (Throwable) {
            return;
        }

        if ($file === false || ! is_file($file)) {
            return;
        }

        $ast = (new FileParser)->parse($file);
        if ($ast === null) {
            return;
        }

        $finder = new NodeFinder;
        $hasBaseUri = $finder->findFirst($ast, function (Node $node): bool {
            if ($node instanceof String_ && strtolower($node->value) === 'base-uri') {
                return true;
            }
            if (
                $node instanceof ClassConstFetch
                && $node->class instanceof Name
                && str_ends_with(ltrim($node->class->toString(), '\\'), 'Directive')
                && $node->name instanceof Identifier
                && strtoupper($node->name->toString()) === 'BASE'
            ) {
                return true;
            }

            return false;
        });

        if ($hasBaseUri !== null) {
            return;
        }

        yield new Finding(
            checkId: $this->id(),
            severity: $this->severity(),
            message: "CSP policy {$policyClass} is missing a base-uri directive — <base> tag injection can redirect relative URLs to attacker-controlled domains.",
            file: str_replace($this->app->basePath().DIRECTORY_SEPARATOR, '', $file),
        );
    }
}

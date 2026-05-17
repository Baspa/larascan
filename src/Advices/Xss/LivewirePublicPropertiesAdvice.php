<?php

declare(strict_types=1);

namespace Baspa\Larascan\Advices\Xss;

use Baspa\Larascan\Support\AbstractAdvice;
use Baspa\Larascan\Support\AdviceEvidence;
use Baspa\Larascan\Support\AdviceOutcome;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use PhpParser\Node\AttributeGroup;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\Property;
use PhpParser\NodeFinder;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

class LivewirePublicPropertiesAdvice extends AbstractAdvice
{
    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'advise.livewire-public-properties';
    }

    public function category(): Category
    {
        return Category::Xss;
    }

    public function name(): string
    {
        return 'Livewire public properties must be validated — treat them as POST data';
    }

    public function isApplicable(): bool
    {
        return class_exists('Livewire\\Component');
    }

    public function run(): AdviceOutcome
    {
        if (! $this->isApplicable()) {
            return AdviceOutcome::skipped('livewire/livewire not installed');
        }

        $scanDirs = [
            $this->appPath.'/Livewire',
            $this->appPath.'/Http/Livewire',
        ];

        $finder = new NodeFinder;
        $evidence = [];

        foreach ($scanDirs as $dir) {
            if (! is_dir($dir)) {
                continue;
            }

            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
            );

            foreach ($iterator as $file) {
                if (! $file instanceof SplFileInfo || ! $file->isFile() || $file->getExtension() !== 'php') {
                    continue;
                }

                $ast = $this->parser->parse($file->getPathname());
                if ($ast === null) {
                    continue;
                }

                /** @var array<int, Class_> $classes */
                $classes = $finder->findInstanceOf($ast, Class_::class);
                foreach ($classes as $class) {
                    if (! $this->extendsLivewireComponent($class)) {
                        continue;
                    }
                    if ($this->classHasRulesProtection($class, $finder)) {
                        continue;
                    }

                    $publicProps = $this->collectPublicProperties($class);
                    if ($publicProps === []) {
                        continue;
                    }

                    $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $file->getPathname());
                    $list = implode(', ', $publicProps);
                    $className = $class->name?->toString() ?? '(anonymous)';

                    $evidence[] = new AdviceEvidence(
                        message: "{$className}: public {$list}",
                        file: $relative,
                        line: $class->getStartLine(),
                    );
                }
            }
        }

        if ($evidence === []) {
            return AdviceOutcome::notSurfaced();
        }

        return AdviceOutcome::surfaced(
            sprintf('%d Livewire component(s) have unvalidated public properties.', count($evidence)),
            $evidence,
        );
    }

    private function extendsLivewireComponent(Class_ $class): bool
    {
        $extends = $class->extends?->toString();
        if ($extends === null) {
            return false;
        }
        $normalized = ltrim($extends, '\\');

        return $normalized === 'Component' || $normalized === 'Livewire\\Component';
    }

    private function classHasRulesProtection(Class_ $class, NodeFinder $finder): bool
    {
        foreach ($class->stmts as $stmt) {
            if ($stmt instanceof Property && $stmt->isProtected()) {
                foreach ($stmt->props as $prop) {
                    if ($prop->name->toString() === 'rules') {
                        return true;
                    }
                }
            }
        }

        $attrs = $finder->findInstanceOf([$class], AttributeGroup::class);
        foreach ($attrs as $group) {
            foreach ($group->attrs as $attr) {
                if (str_ends_with(ltrim($attr->name->toString(), '\\'), 'Validate')) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @return array<int, string>
     */
    private function collectPublicProperties(Class_ $class): array
    {
        $names = [];
        foreach ($class->stmts as $stmt) {
            if (! $stmt instanceof Property) {
                continue;
            }
            if (! $stmt->isPublic()) {
                continue;
            }
            foreach ($stmt->props as $prop) {
                $names[] = '$'.$prop->name->toString();
            }
        }

        return $names;
    }
}

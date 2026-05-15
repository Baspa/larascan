<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Auth;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\Property;
use PhpParser\NodeFinder;

final class PasswordColumnPlainCheck extends AbstractCheck
{
    public function __construct(
        private readonly string $appPath,
        private readonly FileParser $parser,
    ) {}

    public function id(): string
    {
        return 'auth.password-column-plain';
    }

    public function category(): Category
    {
        return Category::Auth;
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function name(): string
    {
        return 'User model should hash passwords and hide them from serialization';
    }

    public function isApplicable(): bool
    {
        return is_dir($this->appPath.'/Models')
            || is_file($this->appPath.'/User.php')
            || is_file($this->appPath.'/Models/User.php');
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        $candidates = [
            $this->appPath.'/Models/User.php',
            $this->appPath.'/User.php',
        ];

        $userFile = null;
        foreach ($candidates as $candidate) {
            if (is_file($candidate)) {
                $userFile = $candidate;
                break;
            }
        }

        if ($userFile === null) {
            return;
        }

        $ast = $this->parser->parse($userFile);
        if ($ast === null) {
            return;
        }

        $finder = new NodeFinder;

        /** @var array<int, Class_> $classes */
        $classes = $finder->findInstanceOf($ast, Class_::class);

        if ($classes === []) {
            return;
        }

        $hasPasswordHidden = false;
        $hasPasswordHashedCast = false;

        foreach ($classes as $class) {
            /** @var array<int, Property> $properties */
            $properties = $finder->findInstanceOf($class->stmts, Property::class);

            foreach ($properties as $property) {
                foreach ($property->props as $prop) {
                    $propName = $prop->name->toString();

                    if ($propName === 'hidden' && $prop->default instanceof Array_) {
                        if ($this->arrayContainsValue($prop->default, 'password')) {
                            $hasPasswordHidden = true;
                        }
                    }

                    if ($propName === 'casts' && $prop->default instanceof Array_) {
                        if ($this->arrayHasKeyWithValue($prop->default, 'password', 'hashed')) {
                            $hasPasswordHashedCast = true;
                        }
                    }
                }
            }
        }

        if ($hasPasswordHidden || $hasPasswordHashedCast) {
            return;
        }

        $relative = str_replace(dirname($this->appPath).DIRECTORY_SEPARATOR, '', $userFile);

        yield new Finding(
            checkId: $this->id(),
            severity: $this->severity(),
            message: "User model in {$relative} doesn't appear to mark 'password' as hidden or use the 'hashed' cast — verify password storage is hashed and not exposed in API responses.",
            file: $relative,
        );
    }

    private function arrayContainsValue(Array_ $array, string $needle): bool
    {
        foreach ($array->items as $item) {
            if ($item === null) {
                continue;
            }

            if ($item->value instanceof String_ && $item->value->value === $needle) {
                return true;
            }
        }

        return false;
    }

    private function arrayHasKeyWithValue(Array_ $array, string $key, string $value): bool
    {
        foreach ($array->items as $item) {
            if ($item === null || $item->key === null) {
                continue;
            }

            if (! $item->key instanceof String_ || $item->key->value !== $key) {
                continue;
            }

            if ($item->value instanceof String_ && $item->value->value === $value) {
                return true;
            }
        }

        return false;
    }
}

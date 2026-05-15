<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

use Baspa\Larascan\Contracts\Check;
use InvalidArgumentException;

final class CheckRegistry
{
    /** @var array<string, Check> */
    private array $checks = [];

    /**
     * @param  array<string, array{enabled?: bool}>  $config
     */
    public function __construct(
        private readonly array $config = [],
    ) {}

    public function register(Check $check): void
    {
        $id = $check->id();
        if (isset($this->checks[$id])) {
            throw new InvalidArgumentException("Check '{$id}' is already registered.");
        }
        $this->checks[$id] = $check;
    }

    /**
     * @return array<int, Check>
     */
    public function all(): array
    {
        return array_values($this->checks);
    }

    /**
     * @return array<int, Check>
     */
    public function enabled(): array
    {
        return array_values(array_filter(
            $this->checks,
            fn (Check $c) => ($this->config[$c->id()]['enabled'] ?? true) === true,
        ));
    }

    /**
     * @param  array<int, string>  $patterns
     * @return iterable<Check>
     */
    public function matching(array $patterns): iterable
    {
        foreach ($this->checks as $id => $check) {
            foreach ($patterns as $pattern) {
                $regex = '/^'.str_replace('\\*', '.*', preg_quote($pattern, '/')).'$/';
                if (preg_match($regex, $id) === 1) {
                    yield $check;

                    continue 2;
                }
            }
        }
    }

    /**
     * @return iterable<Check>
     */
    public function forCategory(Category $category): iterable
    {
        foreach ($this->checks as $check) {
            if ($check->category() === $category) {
                yield $check;
            }
        }
    }
}

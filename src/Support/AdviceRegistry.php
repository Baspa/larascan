<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

use Baspa\Larascan\Contracts\Advice;
use InvalidArgumentException;

final class AdviceRegistry
{
    /** @var array<string, Advice> */
    private array $advices = [];

    /**
     * @param  array<string, array{enabled?: bool}>  $config
     */
    public function __construct(
        private readonly array $config = [],
    ) {}

    public function register(Advice $advice): void
    {
        $id = $advice->id();
        if (isset($this->advices[$id])) {
            throw new InvalidArgumentException("Advice '{$id}' is already registered.");
        }
        $this->advices[$id] = $advice;
    }

    /**
     * @return array<int, Advice>
     */
    public function all(): array
    {
        return array_values($this->advices);
    }

    /**
     * @return array<int, Advice>
     */
    public function enabled(): array
    {
        return array_values(array_filter(
            $this->advices,
            fn (Advice $a) => ($this->config[$a->id()]['enabled'] ?? true) === true,
        ));
    }

    /**
     * @param  array<int, string>  $patterns
     * @return iterable<Advice>
     */
    public function matching(array $patterns): iterable
    {
        foreach ($this->advices as $id => $advice) {
            foreach ($patterns as $pattern) {
                $regex = '/^'.str_replace('\\*', '.*', preg_quote($pattern, '/')).'$/';
                if (preg_match($regex, $id) === 1) {
                    yield $advice;

                    continue 2;
                }
            }
        }
    }

    /**
     * @return iterable<Advice>
     */
    public function forCategory(Category $category): iterable
    {
        foreach ($this->advices as $advice) {
            if ($advice->category() === $category) {
                yield $advice;
            }
        }
    }
}

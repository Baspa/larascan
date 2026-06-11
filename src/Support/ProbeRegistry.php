<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

use Baspa\Larascan\Contracts\Probe;
use InvalidArgumentException;

final class ProbeRegistry
{
    /** @var array<string, Probe> */
    private array $probes = [];

    /**
     * @param  array<string, array{enabled?: bool}>  $config
     */
    public function __construct(
        private readonly array $config = [],
    ) {}

    public function register(Probe $probe): void
    {
        $id = $probe->id();
        if (isset($this->probes[$id])) {
            throw new InvalidArgumentException("Probe '{$id}' is already registered.");
        }
        $this->probes[$id] = $probe;
    }

    /**
     * @return array<int, Probe>
     */
    public function all(): array
    {
        return array_values($this->probes);
    }

    /**
     * @return array<int, Probe>
     */
    public function enabled(): array
    {
        return array_values(array_filter(
            $this->probes,
            fn (Probe $p) => ($this->config[$p->id()]['enabled'] ?? true) === true,
        ));
    }

    /**
     * @param  array<int, string>  $patterns
     * @return iterable<Probe>
     */
    public function matching(array $patterns): iterable
    {
        foreach ($this->probes as $id => $probe) {
            foreach ($patterns as $pattern) {
                $regex = '/^'.str_replace('\\*', '.*', preg_quote($pattern, '/')).'$/';
                if (preg_match($regex, $id) === 1) {
                    yield $probe;

                    continue 2;
                }
            }
        }
    }
}

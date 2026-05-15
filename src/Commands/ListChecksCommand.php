<?php

declare(strict_types=1);

namespace Baspa\Larascan\Commands;

use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\CheckRegistry;
use Illuminate\Console\Command;

class ListChecksCommand extends Command
{
    protected $signature = 'larascan:list
        {--category= : Filter by category}';

    protected $description = 'List all registered larascan checks';

    public function handle(CheckRegistry $registry): int
    {
        $categoryRaw = $this->option('category');
        $category = null;
        if (is_string($categoryRaw) && $categoryRaw !== '') {
            $category = Category::tryFrom($categoryRaw);
            if ($category === null) {
                $this->error("Unknown category: {$categoryRaw}");

                return 2;
            }
        }

        $checks = $category !== null
            ? iterator_to_array($registry->forCategory($category))
            : $registry->all();

        $rows = [];
        foreach ($checks as $check) {
            $rows[] = [
                $check->id(),
                $check->category()->value,
                $check->severity()->value,
                $check->name(),
            ];
        }

        $this->table(['ID', 'Category', 'Severity', 'Name'], $rows);

        return 0;
    }
}

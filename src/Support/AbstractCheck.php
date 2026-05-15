<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

use Baspa\Larascan\Contracts\Check;

abstract class AbstractCheck implements Check
{
    public function isApplicable(): bool
    {
        return true;
    }

    public function docsUrl(): string
    {
        [$cat, $id] = explode('.', $this->id(), 2);
        return "https://github.com/baspa/larascan/blob/main/docs/checks/{$cat}/{$id}.md";
    }
}

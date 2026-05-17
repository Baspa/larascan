<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

use Baspa\Larascan\Contracts\Advice;

abstract class AbstractAdvice implements Advice
{
    public function isApplicable(): bool
    {
        return true;
    }

    public function docsUrl(): string
    {
        $slug = str_contains($this->id(), '.')
            ? explode('.', $this->id(), 2)[1]
            : $this->id();

        return "https://github.com/baspa/larascan/blob/main/docs/advices/{$this->category()->value}/{$slug}.md";
    }
}

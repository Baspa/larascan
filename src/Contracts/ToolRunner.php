<?php

declare(strict_types=1);

namespace Baspa\Larascan\Contracts;

interface ToolRunner
{
    /**
     * Whether the underlying binary/dependency is available on this system.
     *
     * Used by consuming Checks to decide isApplicable().
     */
    public function isAvailable(): bool;
}

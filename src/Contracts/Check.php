<?php

declare(strict_types=1);

namespace Baspa\Larascan\Contracts;

use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;

interface Check
{
    public function id(): string;

    public function category(): Category;

    public function severity(): Severity;

    public function name(): string;

    public function docsUrl(): string;

    public function isApplicable(): bool;

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable;
}

<?php

declare(strict_types=1);

namespace Baspa\Larascan\Contracts;

use Baspa\Larascan\Support\AdviceOutcome;
use Baspa\Larascan\Support\Category;

interface Advice
{
    public function id(): string;

    public function category(): Category;

    public function name(): string;

    public function isApplicable(): bool;

    public function docsUrl(): string;

    public function run(): AdviceOutcome;
}

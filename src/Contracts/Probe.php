<?php

declare(strict_types=1);

namespace Baspa\Larascan\Contracts;

use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\Severity;

interface Probe
{
    public function id(): string;

    public function severity(): Severity;

    public function name(): string;

    public function docsUrl(): string;

    public function applies(ProbeContext $context): bool;

    public function skipReason(): string;

    /**
     * @return iterable<Finding>
     */
    public function evaluate(ProbeContext $context): iterable;
}

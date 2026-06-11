<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

use Baspa\Larascan\Contracts\Probe;

abstract class AbstractProbe implements Probe
{
    public function applies(ProbeContext $context): bool
    {
        return true;
    }

    public function skipReason(): string
    {
        return '';
    }

    public function docsUrl(): string
    {
        $slug = str_contains($this->id(), '.')
            ? explode('.', $this->id(), 2)[1]
            : $this->id();

        return "https://github.com/baspa/larascan/blob/main/docs/probes/{$slug}.md";
    }

    /**
     * Downgrade a finding to Info when probing a local target, otherwise keep
     * its real severity.
     */
    protected function severityFor(ProbeContext $context, Severity $remote): Severity
    {
        return $context->isLocal ? Severity::Info : $remote;
    }
}

<?php

declare(strict_types=1);

namespace Baspa\Larascan\Probes;

use Baspa\Larascan\Support\AbstractProbe;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\Severity;

final class XFrameOptionsProbe extends AbstractProbe
{
    public function id(): string
    {
        return 'probe.x-frame-options';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'Clickjacking protection via X-Frame-Options or CSP frame-ancestors';
    }

    /**
     * @return iterable<Finding>
     */
    public function evaluate(ProbeContext $context): iterable
    {
        $value = $context->header('X-Frame-Options');
        if ($value !== null && in_array(strtoupper(trim($value)), ['DENY', 'SAMEORIGIN'], true)) {
            return;
        }

        $csp = $context->header('Content-Security-Policy');
        if ($csp !== null && stripos($csp, 'frame-ancestors') !== false) {
            return;
        }

        yield new Finding(
            checkId: $this->id(),
            severity: $this->severityFor($context, Severity::Medium),
            message: 'No clickjacking protection — set X-Frame-Options to DENY/SAMEORIGIN or use a CSP frame-ancestors directive.',
        );
    }
}

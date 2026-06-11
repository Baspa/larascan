<?php

declare(strict_types=1);

namespace Baspa\Larascan\Probes;

use Baspa\Larascan\Support\AbstractProbe;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\Severity;

final class ReferrerPolicyProbe extends AbstractProbe
{
    public function id(): string
    {
        return 'probe.referrer-policy';
    }

    public function severity(): Severity
    {
        return Severity::Low;
    }

    public function name(): string
    {
        return 'Referrer-Policy header is present and not unsafe-url';
    }

    /**
     * @return iterable<Finding>
     */
    public function evaluate(ProbeContext $context): iterable
    {
        $value = $context->header('Referrer-Policy');

        if ($value === null) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severityFor($context, Severity::Low),
                message: 'Response is missing the Referrer-Policy header — referrer information may leak to third parties.',
            );

            return;
        }

        if (strtolower(trim($value)) === 'unsafe-url') {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severityFor($context, Severity::Low),
                message: 'Referrer-Policy is "unsafe-url" — the full URL is sent as the referrer even to insecure destinations.',
            );
        }
    }
}

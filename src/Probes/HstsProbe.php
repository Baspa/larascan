<?php

declare(strict_types=1);

namespace Baspa\Larascan\Probes;

use Baspa\Larascan\Support\AbstractProbe;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\Severity;

final class HstsProbe extends AbstractProbe
{
    private const MIN_MAX_AGE = 15552000;

    public function id(): string
    {
        return 'probe.hsts';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'Strict-Transport-Security header is present with a sufficient max-age';
    }

    public function applies(ProbeContext $context): bool
    {
        return $context->isHttps;
    }

    public function skipReason(): string
    {
        return 'target is not HTTPS';
    }

    /**
     * @return iterable<Finding>
     */
    public function evaluate(ProbeContext $context): iterable
    {
        $value = $context->header('Strict-Transport-Security');

        if ($value === null) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severityFor($context, Severity::High),
                message: 'Response is missing the Strict-Transport-Security header — browsers will not enforce HTTPS-only access.',
            );

            return;
        }

        if (preg_match('/max-age\s*=\s*"?(\d+)/i', $value, $m) === 1 && (int) $m[1] < self::MIN_MAX_AGE) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severityFor($context, Severity::Low),
                message: sprintf('Strict-Transport-Security max-age is %d seconds — below the recommended minimum of %d (180 days).', (int) $m[1], self::MIN_MAX_AGE),
            );
        }
    }
}

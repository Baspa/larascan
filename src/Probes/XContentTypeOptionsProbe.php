<?php

declare(strict_types=1);

namespace Baspa\Larascan\Probes;

use Baspa\Larascan\Support\AbstractProbe;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\Severity;

final class XContentTypeOptionsProbe extends AbstractProbe
{
    public function id(): string
    {
        return 'probe.x-content-type-options';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'X-Content-Type-Options header is set to nosniff';
    }

    /**
     * @return iterable<Finding>
     */
    public function evaluate(ProbeContext $context): iterable
    {
        $value = $context->header('X-Content-Type-Options');

        if ($value === null || strtolower(trim($value)) !== 'nosniff') {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severityFor($context, Severity::Medium),
                message: $value === null
                    ? 'Response is missing the X-Content-Type-Options header — set it to "nosniff" to stop MIME-type sniffing.'
                    : sprintf('X-Content-Type-Options is "%s" — it must be exactly "nosniff".', $value),
            );
        }
    }
}

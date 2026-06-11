<?php

declare(strict_types=1);

namespace Baspa\Larascan\Probes;

use Baspa\Larascan\Support\AbstractProbe;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\Severity;

final class HttpsRedirectProbe extends AbstractProbe
{
    private const REDIRECT_STATUSES = [301, 302, 307, 308];

    public function id(): string
    {
        return 'probe.https-redirect';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'Plain HTTP requests are redirected to HTTPS';
    }

    public function applies(ProbeContext $context): bool
    {
        return $context->httpRedirect !== null;
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
        $redirect = $context->httpRedirect;
        if ($redirect === null) {
            return;
        }

        $status = $redirect['status'];
        $location = $redirect['location'];

        $redirectsToHttps = in_array($status, self::REDIRECT_STATUSES, true)
            && $location !== null
            && str_starts_with(strtolower($location), 'https://');

        if (! $redirectsToHttps) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severityFor($context, Severity::High),
                message: sprintf('Plain HTTP request returned status %d%s — it must redirect (301/302/307/308) to an https:// URL.', $status, $location !== null ? ' to "'.$location.'"' : ''),
            );
        }
    }
}

<?php

declare(strict_types=1);

namespace Baspa\Larascan\Probes;

use Baspa\Larascan\Support\AbstractProbe;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\Severity;

final class CspProbe extends AbstractProbe
{
    public function id(): string
    {
        return 'probe.csp';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'Content-Security-Policy is present and script-src has no unguarded unsafe-inline';
    }

    /**
     * @return iterable<Finding>
     */
    public function evaluate(ProbeContext $context): iterable
    {
        $csp = $context->header('Content-Security-Policy');

        if ($csp === null) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severityFor($context, Severity::Medium),
                message: 'Response is missing the Content-Security-Policy header — without a CSP the browser cannot constrain script sources.',
            );

            return;
        }

        $scriptSrc = $this->directive($csp, 'script-src');
        if ($scriptSrc === null) {
            return;
        }

        $hasUnsafeInline = stripos($scriptSrc, "'unsafe-inline'") !== false;
        $hasNonceOrHash = stripos($scriptSrc, "'nonce-") !== false
            || stripos($scriptSrc, "'sha256-") !== false
            || stripos($scriptSrc, "'sha384-") !== false
            || stripos($scriptSrc, "'sha512-") !== false;

        if ($hasUnsafeInline && ! $hasNonceOrHash) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severityFor($context, Severity::Medium),
                message: "Content-Security-Policy script-src allows 'unsafe-inline' without a nonce or hash — inline scripts are not protected against XSS.",
            );
        }
    }

    private function directive(string $csp, string $name): ?string
    {
        foreach (explode(';', $csp) as $segment) {
            $segment = trim($segment);
            if (stripos($segment, $name) === 0) {
                $rest = substr($segment, strlen($name));
                // Ensure an exact directive-name match (not script-src-elem etc.).
                if ($rest === '' || $rest[0] === ' ') {
                    return trim($rest);
                }
            }
        }

        return null;
    }
}

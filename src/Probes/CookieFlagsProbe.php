<?php

declare(strict_types=1);

namespace Baspa\Larascan\Probes;

use Baspa\Larascan\Support\AbstractProbe;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\Severity;

final class CookieFlagsProbe extends AbstractProbe
{
    public function id(): string
    {
        return 'probe.cookie-flags';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'Set-Cookie flags (Secure, HttpOnly, SameSite) are correctly applied';
    }

    /**
     * @return iterable<Finding>
     */
    public function evaluate(ProbeContext $context): iterable
    {
        foreach ($context->cookies as $cookie) {
            $name = $cookie['name'];

            if ($context->isHttps && ! $cookie['secure']) {
                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severityFor($context, Severity::High),
                    message: sprintf('Cookie "%s" is missing the Secure flag — it may be transmitted over plain HTTP.', $name),
                );
            }

            if ($this->isSessionCookie($name) && ! $cookie['httponly']) {
                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severityFor($context, Severity::High),
                    message: sprintf('Session cookie "%s" is missing the HttpOnly flag — it is readable by JavaScript and exposed to XSS theft.', $name),
                );
            }

            if ($cookie['samesite'] === null) {
                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severityFor($context, Severity::Medium),
                    message: sprintf('Cookie "%s" is missing the SameSite attribute — it offers no CSRF protection by default.', $name),
                );
            }
        }
    }

    private function isSessionCookie(string $name): bool
    {
        $lower = strtolower($name);

        return $lower === 'laravel_session' || str_ends_with($lower, '_session');
    }
}

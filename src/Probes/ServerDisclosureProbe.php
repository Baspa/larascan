<?php

declare(strict_types=1);

namespace Baspa\Larascan\Probes;

use Baspa\Larascan\Support\AbstractProbe;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ProbeContext;
use Baspa\Larascan\Support\Severity;

final class ServerDisclosureProbe extends AbstractProbe
{
    public function id(): string
    {
        return 'probe.server-disclosure';
    }

    public function severity(): Severity
    {
        return Severity::Low;
    }

    public function name(): string
    {
        return 'Server software versions are not disclosed via response headers';
    }

    /**
     * @return iterable<Finding>
     */
    public function evaluate(ProbeContext $context): iterable
    {
        $poweredBy = $context->header('X-Powered-By');
        if ($poweredBy !== null) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severityFor($context, Severity::Low),
                message: sprintf('X-Powered-By header is exposed ("%s") — it discloses the runtime stack to attackers.', $poweredBy),
            );
        }

        $server = $context->header('Server');
        if ($server !== null && preg_match('/\d/', $server) === 1) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severityFor($context, Severity::Low),
                message: sprintf('Server header discloses a version number ("%s") — strip the version to avoid fingerprinting.', $server),
            );
        }
    }
}

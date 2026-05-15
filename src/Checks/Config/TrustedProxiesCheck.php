<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Config;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class TrustedProxiesCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'config.trusted-proxies';
    }

    public function category(): Category
    {
        return Category::Config;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'Trusted proxies must not be wildcard';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        /** @var Repository $config */
        $config = $this->app->make('config');

        $proxies = $config->get('trustedproxy.proxies');
        if ($proxies === '*' || (is_array($proxies) && in_array('*', $proxies, true))) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: 'Trusted proxies includes wildcard (*) — every X-Forwarded-* header from any source is honored, enabling IP/host spoofing.',
            );
        }
    }
}

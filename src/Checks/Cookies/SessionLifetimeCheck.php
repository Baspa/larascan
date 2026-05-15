<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Cookies;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class SessionLifetimeCheck extends AbstractCheck
{
    private const MIN_MINUTES = 1;

    private const MAX_MINUTES = 525600;

    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'cookies.session-lifetime';
    }

    public function category(): Category
    {
        return Category::Cookies;
    }

    public function severity(): Severity
    {
        return Severity::Low;
    }

    public function name(): string
    {
        return 'session.lifetime must be within a reasonable range';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        /** @var Repository $config */
        $config = $this->app->make('config');

        $lifetime = $config->get('session.lifetime');
        if (! is_int($lifetime) && ! (is_string($lifetime) && ctype_digit($lifetime))) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: 'session.lifetime is not a positive integer.',
            );

            return;
        }

        $minutes = (int) $lifetime;
        if ($minutes < self::MIN_MINUTES || $minutes > self::MAX_MINUTES) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: sprintf(
                    'session.lifetime is %d minutes — outside the sensible range of %d to %d minutes.',
                    $minutes,
                    self::MIN_MINUTES,
                    self::MAX_MINUTES,
                ),
            );
        }
    }
}

<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Injection;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class HostHeaderCheck extends AbstractCheck
{
    /**
     * @var array<int, string>
     */
    private const LOCAL_NEEDLES = ['localhost', '127.0.0.1', '0.0.0.0'];

    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'injection.host-header';
    }

    public function category(): Category
    {
        return Category::Injection;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'app.url must be set and not point to localhost in production';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        /** @var Repository $config */
        $config = $this->app->make('config');

        $url = $config->get('app.url');
        $env = (string) ($config->get('app.env') ?? '');

        $isMissing = ! is_string($url) || trim($url) === '';
        $isLocal = is_string($url) && $this->containsLocalHost($url);

        if (! $isMissing && ! $isLocal) {
            return;
        }

        yield new Finding(
            checkId: $this->id(),
            severity: $this->severity()->downgradeIfNotProduction($env),
            message: 'app.url is not set or points to localhost — host header injection can redirect users, set cookies, generate signed URLs, and poison password reset emails.',
        );
    }

    private function containsLocalHost(string $url): bool
    {
        $lower = strtolower($url);

        foreach (self::LOCAL_NEEDLES as $needle) {
            if (str_contains($lower, $needle)) {
                return true;
            }
        }

        return false;
    }
}

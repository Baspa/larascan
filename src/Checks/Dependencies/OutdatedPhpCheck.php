<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Dependencies;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use DateInterval;
use DateTimeImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

class OutdatedPhpCheck extends AbstractCheck
{
    /**
     * From https://www.php.net/supported-versions.php. 8.6 is not listed there yet,
     * so it follows the documented two years of active and two of security support.
     */
    private const SUPPORT = [
        '8.3' => ['active' => '2025-12-31', 'security' => '2027-12-31'],
        '8.4' => ['active' => '2026-12-31', 'security' => '2028-12-31'],
        '8.5' => ['active' => '2027-12-31', 'security' => '2029-12-31'],
        '8.6' => ['active' => '2028-12-31', 'security' => '2030-12-31'],
    ];

    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'dependencies.outdated-php';
    }

    public function category(): Category
    {
        return Category::Dependencies;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'PHP version past active support or near end-of-life';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        $versionId = $this->phpVersionId();
        $support = self::SUPPORT[sprintf('%d.%d', intdiv($versionId, 10000), intdiv($versionId, 100) % 100)] ?? null;

        if ($support === null) {
            return;
        }

        $today = $this->today();
        $date = $today->format('Y-m-d');
        $inOneYear = $today->add(new DateInterval('P1Y'))->format('Y-m-d');

        [$severity, $status] = match (true) {
            $date > $support['security'] => [Severity::High, "is end-of-life: security support ended on {$support['security']}"],
            $inOneYear >= $support['security'] => [Severity::High, "is near end-of-life: security support ends on {$support['security']}"],
            $date > $support['active'] => [Severity::Medium, "only receives security fixes, which stop on {$support['security']}"],
            default => [null, ''],
        };

        if ($severity === null) {
            return;
        }

        /** @var Repository $config */
        $config = $this->app->make('config');
        $env = (string) ($config->get('app.env') ?? '');

        yield new Finding(
            checkId: $this->id(),
            severity: $severity->downgradeIfNotProduction($env),
            message: sprintf('PHP %s %s — %s.', $this->phpVersionString(), $status, $this->upgradeAdvice($date)),
        );
    }

    protected function phpVersionId(): int
    {
        return PHP_VERSION_ID;
    }

    protected function phpVersionString(): string
    {
        return PHP_VERSION;
    }

    protected function today(): DateTimeImmutable
    {
        return new DateTimeImmutable('today');
    }

    private function upgradeAdvice(string $date): string
    {
        foreach (self::SUPPORT as $branch => $support) {
            if ($date <= $support['active']) {
                return "upgrade to PHP {$branch}, the oldest branch still in active support";
            }
        }

        return 'upgrade to a newer PHP branch';
    }
}

<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Dependencies;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

class OutdatedPhpCheck extends AbstractCheck
{
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
        return 'PHP version at or near end-of-life';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        if ($this->phpVersionId() >= 80200) {
            return;
        }

        /** @var Repository $config */
        $config = $this->app->make('config');
        $env = (string) ($config->get('app.env') ?? '');

        yield new Finding(
            checkId: $this->id(),
            severity: $this->severity()->downgradeIfNotProduction($env),
            message: sprintf(
                'PHP version %s is at or near end-of-life — upgrade to PHP 8.3 or 8.4 for security patches.',
                $this->phpVersionString(),
            ),
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
}

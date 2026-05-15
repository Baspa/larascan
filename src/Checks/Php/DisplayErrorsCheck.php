<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Php;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

class DisplayErrorsCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'php.display-errors';
    }

    public function category(): Category
    {
        return Category::Php;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'display_errors must be off in production to avoid leaking stack traces';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        $value = $this->iniValue();

        if (filter_var($value, FILTER_VALIDATE_BOOLEAN)) {
            /** @var Repository $config */
            $config = $this->app->make('config');
            $env = (string) ($config->get('app.env') ?? '');

            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity()->downgradeIfNotProduction($env),
                message: 'display_errors is on — fatal errors and stack traces leak to the browser, exposing application internals.',
            );
        }
    }

    protected function iniValue(): string|false
    {
        return ini_get('display_errors');
    }
}

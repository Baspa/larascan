<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Php;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Foundation\Application;

class ExposePhpCheck extends AbstractCheck
{
    public function __construct(
        // Property injected for DI consistency with other checks in this category.
        // @phpstan-ignore-next-line property.onlyWritten
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'php.expose-php';
    }

    public function category(): Category
    {
        return Category::Php;
    }

    public function severity(): Severity
    {
        return Severity::Low;
    }

    public function name(): string
    {
        return 'expose_php must be off to avoid leaking the PHP version';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        $value = $this->iniValue();

        if (filter_var($value, FILTER_VALIDATE_BOOLEAN)) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: 'expose_php is on — server response headers (X-Powered-By) leak the PHP version, helping attackers fingerprint your stack.',
            );
        }
    }

    protected function iniValue(): string|false
    {
        return ini_get('expose_php');
    }
}

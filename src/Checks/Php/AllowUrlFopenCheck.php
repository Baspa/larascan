<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Php;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Foundation\Application;

class AllowUrlFopenCheck extends AbstractCheck
{
    public function __construct(
        // Property injected for DI consistency with other checks in this category.
        // @phpstan-ignore-next-line property.onlyWritten
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'php.allow-url-fopen';
    }

    public function category(): Category
    {
        return Category::Php;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function name(): string
    {
        return 'allow_url_fopen should be off to prevent SSRF via file functions';
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
                message: 'allow_url_fopen is on — file functions can be tricked into reading remote URLs, enabling SSRF and credential exfiltration via file:// or http:// wrappers.',
            );
        }
    }

    protected function iniValue(): string|false
    {
        return ini_get('allow_url_fopen');
    }
}

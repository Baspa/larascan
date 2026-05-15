<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Logging;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;

final class CustomErrorPagesCheck extends AbstractCheck
{
    /**
     * @var array<int, string>
     */
    private const REQUIRED_PAGES = ['500', '503'];

    public function __construct(
        private readonly string $basePath,
    ) {}

    public function id(): string
    {
        return 'logging.custom-error-pages';
    }

    public function category(): Category
    {
        return Category::Logging;
    }

    public function severity(): Severity
    {
        return Severity::Low;
    }

    public function name(): string
    {
        return 'Custom 500/503 error pages prevent default Laravel error page from leaking debug info';
    }

    public function isApplicable(): bool
    {
        return is_dir($this->basePath.'/resources/views');
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        foreach (self::REQUIRED_PAGES as $code) {
            $relative = "resources/views/errors/{$code}.blade.php";
            $path = $this->basePath.'/'.$relative;

            if (! is_file($path)) {
                yield new Finding(
                    checkId: $this->id(),
                    severity: $this->severity(),
                    message: "Custom error page {$relative} is missing — default Laravel error pages may leak Whoops debug info.",
                    file: $relative,
                );
            }
        }
    }
}

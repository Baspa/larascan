<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Crypto;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;

final class CipherNotPinnedCheck extends AbstractCheck
{
    public function __construct(
        private readonly string $configPath,
    ) {}

    public function id(): string
    {
        return 'crypto.cipher-not-pinned';
    }

    public function category(): Category
    {
        return Category::Crypto;
    }

    public function severity(): Severity
    {
        return Severity::Low;
    }

    public function name(): string
    {
        return "config/app.php must pin an explicit 'cipher' value";
    }

    public function isApplicable(): bool
    {
        return is_file($this->configPath.'/app.php');
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        $contents = (string) file_get_contents($this->configPath.'/app.php');

        if (! str_contains($contents, "'cipher' =>") && ! str_contains($contents, '"cipher" =>')) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: "config/app.php does not pin a 'cipher' value — relies on Laravel's default which has changed over major versions (AES-128-CBC → AES-256-CBC). Pin explicitly for upgrade-safety.",
                file: 'config/app.php',
            );
        }
    }
}

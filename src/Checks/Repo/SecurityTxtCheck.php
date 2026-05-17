<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Repo;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;

final class SecurityTxtCheck extends AbstractCheck
{
    public function __construct(
        private readonly string $publicPath,
    ) {}

    public function id(): string
    {
        return 'repo.security-txt';
    }

    public function category(): Category
    {
        return Category::Repo;
    }

    public function severity(): Severity
    {
        return Severity::Low;
    }

    public function name(): string
    {
        return 'public/.well-known/security.txt should be present so researchers know how to report vulnerabilities';
    }

    public function isApplicable(): bool
    {
        return is_dir($this->publicPath);
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        if (is_file($this->publicPath.'/.well-known/security.txt')) {
            return;
        }

        yield new Finding(
            checkId: $this->id(),
            severity: $this->severity(),
            message: 'public/.well-known/security.txt is missing — add a security.txt file so researchers know where to report vulnerabilities. See https://securitytxt.org/.',
        );
    }
}

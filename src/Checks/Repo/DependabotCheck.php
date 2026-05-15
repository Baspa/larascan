<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Repo;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;

final class DependabotCheck extends AbstractCheck
{
    public function __construct(
        private readonly string $basePath,
    ) {}

    public function id(): string
    {
        return 'repo.dependabot';
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
        return 'Dependabot configuration enables automated dependency vulnerability scanning';
    }

    public function isApplicable(): bool
    {
        return is_dir($this->basePath.'/.github');
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        $yml = $this->basePath.'/.github/dependabot.yml';
        $yaml = $this->basePath.'/.github/dependabot.yaml';

        if (is_file($yml) || is_file($yaml)) {
            return;
        }

        yield new Finding(
            checkId: $this->id(),
            severity: $this->severity(),
            message: 'No .github/dependabot.yml configured — automated dependency vulnerability scanning is not enabled for this repo.',
        );
    }
}

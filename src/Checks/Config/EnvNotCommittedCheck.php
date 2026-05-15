<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Config;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Symfony\Component\Process\Process;

final class EnvNotCommittedCheck extends AbstractCheck
{
    public function __construct(
        private readonly string $basePath,
    ) {}

    public function id(): string
    {
        return 'config.env-not-committed';
    }

    public function category(): Category
    {
        return Category::Config;
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function name(): string
    {
        return '.env must be gitignored and never committed';
    }

    public function isApplicable(): bool
    {
        return is_dir($this->basePath.'/.git');
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        if (! $this->envIsGitignored()) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: '.env is not listed in .gitignore — secrets may leak when files are staged.',
            );
        }

        if ($this->envWasCommitted()) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: '.env was committed to git history — rotate all secrets and rewrite history with git filter-repo.',
            );
        }
    }

    private function envIsGitignored(): bool
    {
        $gitignorePath = $this->basePath.'/.gitignore';
        if (! is_file($gitignorePath)) {
            return false;
        }

        $contents = (string) file_get_contents($gitignorePath);
        foreach (explode("\n", $contents) as $line) {
            $trimmed = trim($line);
            if ($trimmed === '.env' || $trimmed === '/.env') {
                return true;
            }
        }

        return false;
    }

    private function envWasCommitted(): bool
    {
        $process = new Process(['git', 'log', '--all', '--full-history', '--', '.env'], $this->basePath);
        $process->setTimeout(15.0);
        $process->run();

        return trim($process->getOutput()) !== '';
    }
}

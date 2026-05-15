<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Repo;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Symfony\Component\Process\Process;

final class GitleaksHistoryCheck extends AbstractCheck
{
    /**
     * @var array<string, string>
     */
    private const SECRET_PATTERNS = [
        'AWS access key' => '/AKIA[0-9A-Z]{16}/',
        'Stripe key' => '/(?:r|s)k_(?:live|test)_[a-zA-Z0-9]{24,}/',
        'GitHub personal access token' => '/ghp_[a-zA-Z0-9]{36}/',
        'Slack bot token' => '/xoxb-[a-zA-Z0-9-]+/',
    ];

    public function __construct(
        private readonly string $basePath,
    ) {}

    public function id(): string
    {
        return 'repo.gitleaks-history';
    }

    public function category(): Category
    {
        return Category::Repo;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'Potential secrets leaked in git history';
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
        $process = new Process(['git', 'log', '-p', '-n', '100'], $this->basePath);
        $process->setTimeout(60.0);
        $process->run();

        if (! $process->isSuccessful()) {
            return;
        }

        $output = $process->getOutput();
        if ($output === '') {
            return;
        }

        $seen = [];

        foreach (self::SECRET_PATTERNS as $secretType => $pattern) {
            if (preg_match_all($pattern, $output, $matches) > 0) {
                foreach ($matches[0] as $match) {
                    $key = $secretType.'|'.$match;
                    if (isset($seen[$key])) {
                        continue;
                    }
                    $seen[$key] = true;

                    yield new Finding(
                        checkId: $this->id(),
                        severity: $this->severity(),
                        message: "Potential secret leak found in git history — pattern matches '{$secretType}'. Rotate credentials and rewrite history. Note: scan limited to last 100 commits.",
                    );
                }
            }
        }
    }
}

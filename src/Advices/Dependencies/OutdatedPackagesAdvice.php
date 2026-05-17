<?php

declare(strict_types=1);

namespace Baspa\Larascan\Advices\Dependencies;

use Baspa\Larascan\Support\AbstractAdvice;
use Baspa\Larascan\Support\AdviceEvidence;
use Baspa\Larascan\Support\AdviceOutcome;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Tools\ComposerOutdatedRunner;
use Baspa\Larascan\Tools\NpmOutdatedRunner;

final class OutdatedPackagesAdvice extends AbstractAdvice
{
    private const MAX_ENTRIES = 10;

    public function __construct(
        private readonly ComposerOutdatedRunner $composer,
        private readonly NpmOutdatedRunner $npm,
    ) {}

    public function id(): string
    {
        return 'advise.outdated-packages';
    }

    public function category(): Category
    {
        return Category::Dependencies;
    }

    public function name(): string
    {
        return 'Run composer/npm outdated regularly — flag direct deps that have available updates';
    }

    public function run(): AdviceOutcome
    {
        $composerAvailable = $this->composer->isAvailable();
        $npmAvailable = $this->npm->isAvailable();

        if (! $composerAvailable && ! $npmAvailable) {
            return AdviceOutcome::skipped('no composer.json or package.json present');
        }

        $evidence = [];

        if ($composerAvailable) {
            foreach (array_slice($this->composer->run(), 0, self::MAX_ENTRIES) as $pkg) {
                $evidence[] = new AdviceEvidence(
                    message: "composer: {$pkg['name']} {$pkg['current']} → {$pkg['latest']} ({$pkg['status']})",
                );
            }
        }

        if ($npmAvailable) {
            foreach (array_slice($this->npm->run(), 0, self::MAX_ENTRIES) as $pkg) {
                $evidence[] = new AdviceEvidence(
                    message: "npm: {$pkg['name']} {$pkg['current']} → {$pkg['latest']}",
                );
            }
        }

        if ($evidence === []) {
            return AdviceOutcome::notSurfaced();
        }

        return AdviceOutcome::surfaced(
            sprintf('%d outdated direct dependencies — review and update.', count($evidence)),
            $evidence,
        );
    }
}

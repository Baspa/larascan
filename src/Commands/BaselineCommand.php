<?php

declare(strict_types=1);

namespace Baspa\Larascan\Commands;

use Baspa\Larascan\Larascan;
use Baspa\Larascan\Support\Baseline;
use Baspa\Larascan\Support\CheckStatus;
use Baspa\Larascan\Support\FindingHasher;
use Baspa\Larascan\Support\ScanOptions;
use Baspa\Larascan\Support\Severity;
use Illuminate\Console\Command;

class BaselineCommand extends Command
{
    protected $signature = 'larascan:baseline
        {--baseline= : Where to write the baseline (default: larascan-baseline.json)}';

    protected $description = 'Write current findings to a baseline file so existing issues stop failing CI';

    public function handle(Larascan $larascan): int
    {
        // Full enabled set, every severity, no baseline applied — the file
        // must capture everything the next plain scan could report.
        $result = $larascan->scan(new ScanOptions(failOn: Severity::Info));

        foreach ($result->statuses() as $checkId => $status) {
            if ($status === CheckStatus::Errored) {
                $this->warn(sprintf(
                    'Check %s errored — its findings are not in the baseline: %s',
                    $checkId,
                    $result->errorOf($checkId) ?? 'unknown',
                ));
            }
        }

        $baseline = Baseline::fromFindings($result->findings(), new FindingHasher);

        $option = $this->option('baseline');
        $path = Baseline::resolvePath(is_string($option) ? $option : null);
        if (file_put_contents($path, $baseline->toJson().PHP_EOL) === false) {
            $this->error("Could not write baseline file: {$path}");

            return 2;
        }

        $checkIds = [];
        foreach ($result->findings() as $f) {
            $checkIds[$f->checkId] = true;
        }

        $this->info(sprintf(
            'Baseline written to %s (%d findings across %d checks).',
            $path,
            $baseline->count(),
            count($checkIds),
        ));

        return 0;
    }
}

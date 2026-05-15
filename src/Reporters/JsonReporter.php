<?php

declare(strict_types=1);

namespace Baspa\Larascan\Reporters;

use Baspa\Larascan\Support\CheckStatus;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ScanResult;
use Symfony\Component\Console\Output\OutputInterface;

final class JsonReporter
{
    public function render(ScanResult $result, OutputInterface $output, bool $onlyFailed = false): void
    {
        $findingsByCheck = [];
        foreach ($result->findings() as $f) {
            $findingsByCheck[$f->checkId][] = $f;
        }

        $checks = [];
        foreach ($result->statuses() as $checkId => $status) {
            if ($onlyFailed && ! in_array($status, [CheckStatus::Failed, CheckStatus::Errored], true)) {
                continue;
            }
            $prefix = explode('.', $checkId, 2)[0];
            $entry = [
                'id' => $checkId,
                'category' => $prefix,
                'status' => $status->value,
                'findings' => array_map(
                    fn (Finding $f) => array_filter([
                        'severity' => $f->severity->value,
                        'message' => $f->message,
                        'file' => $f->file,
                        'line' => $f->line,
                    ], fn ($v) => $v !== null),
                    $findingsByCheck[$checkId] ?? [],
                ),
            ];

            if ($status === CheckStatus::Skipped) {
                $entry['skip_reason'] = $result->skipReasonOf($checkId);
            }
            if ($status === CheckStatus::Errored) {
                $entry['error'] = $result->errorOf($checkId);
            }

            $checks[] = $entry;
        }

        $counts = $result->counts();
        $highest = $result->highestSeverity();

        $payload = [
            'version' => '1.0',
            'summary' => [
                'passed' => $counts['passed'],
                'failed' => $counts['failed'],
                'skipped' => $counts['skipped'],
                'errored' => $counts['errored'],
                'highest_severity' => $highest?->value,
            ],
            'checks' => $checks,
        ];

        $output->writeln((string) json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }
}

<?php

declare(strict_types=1);

namespace Baspa\Larascan\Reporters;

use Baspa\Larascan\Support\CheckStatus;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ScanResult;
use Symfony\Component\Console\Output\OutputInterface;

final class ConsoleReporter
{
    public function render(ScanResult $result, OutputInterface $output): void
    {
        $output->writeln('');
        $output->writeln('<info>larascan — security scan</info>');
        $output->writeln('');

        $findingsByCheck = [];
        foreach ($result->findings() as $f) {
            $findingsByCheck[$f->checkId][] = $f;
        }

        foreach ($result->statuses() as $checkId => $status) {
            $output->writeln(match ($status) {
                CheckStatus::Passed => sprintf('  <fg=green>✓</> %-40s passed', $checkId),
                CheckStatus::Failed => $this->renderFailures($checkId, $findingsByCheck[$checkId] ?? []),
                CheckStatus::Skipped => sprintf(
                    '  <fg=yellow>⊘</> %-40s skipped (%s)',
                    $checkId,
                    $result->skipReasonOf($checkId) ?? 'unknown',
                ),
                CheckStatus::Errored => sprintf(
                    '  <fg=red>!</> %-40s ERROR — %s',
                    $checkId,
                    $result->errorOf($checkId) ?? 'unknown',
                ),
            });
        }

        $counts = $result->counts();
        $output->writeln('');
        $output->writeln('<info>Report</info>');
        $output->writeln(sprintf(
            '  Passed: %d    Failed: %d    Skipped: %d    Errored: %d',
            $counts['passed'],
            $counts['failed'],
            $counts['skipped'],
            $counts['errored'],
        ));
    }

    /**
     * @param  array<int, Finding>  $findings
     */
    private function renderFailures(string $checkId, array $findings): string
    {
        if ($findings === []) {
            return sprintf('  <fg=red>✗</> %-40s FAILED', $checkId);
        }

        $lines = [];
        foreach ($findings as $f) {
            $lines[] = sprintf(
                '  <fg=red>✗</> %-40s %s   %s',
                $checkId,
                strtoupper($f->severity->value),
                $f->message,
            );
        }

        return implode("\n", $lines);
    }
}

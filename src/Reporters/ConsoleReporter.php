<?php

declare(strict_types=1);

namespace Baspa\Larascan\Reporters;

use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\CheckStatus;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ScanResult;
use Symfony\Component\Console\Output\OutputInterface;

use function Termwind\render;
use function Termwind\renderUsing;

final class ConsoleReporter
{
    public function render(ScanResult $result, OutputInterface $output, bool $plain = false): void
    {
        if ($plain) {
            $this->renderPlain($result, $output);

            return;
        }

        renderUsing($output);

        // Compact header
        render('<div class="mx-1 my-1 px-2 bg-blue-600 text-white font-bold">larascan — security scan</div>');

        // Pre-index findings by checkId
        $findingsByCheck = [];
        foreach ($result->findings() as $f) {
            $findingsByCheck[$f->checkId][] = $f;
        }

        // Group statuses by category prefix (preserve insertion order)
        $byCategory = [];
        foreach ($result->statuses() as $checkId => $status) {
            $prefix = explode('.', $checkId, 2)[0];
            $byCategory[$prefix][] = $checkId;
        }

        // Render each category block
        foreach ($byCategory as $prefix => $checkIds) {
            $cat = Category::tryFrom($prefix);
            $label = $cat?->label() ?? ucfirst($prefix);

            render(sprintf(
                '<div class="mt-1 mx-1"><span class="font-bold text-blue-400">%s</span> <span class="text-gray-500">(%s.*)</span></div>',
                htmlspecialchars($label, ENT_QUOTES),
                htmlspecialchars($prefix, ENT_QUOTES),
            ));

            foreach ($checkIds as $checkId) {
                $status = $result->statusOf($checkId);
                if ($status === null) {
                    continue;
                }
                $findings = $findingsByCheck[$checkId] ?? [];
                $this->renderCheckRow($checkId, $status, $findings, $result);
            }
        }

        // Footer / report
        render('<div class="mt-1 mx-1 text-gray-500">──────────────────────────────────────────</div>');
        render('<div class="mx-1 font-bold">Report</div>');
        $counts = $result->counts();
        $highest = $result->highestSeverity();
        render(sprintf(
            '<div class="mx-3">Passed <span class="text-green-500">%d</span>    '
            .'Failed <span class="text-red-500">%d</span>    '
            .'Skipped <span class="text-gray-500">%d</span>    '
            .'Errored <span class="text-red-700">%d</span>    '
            .'Highest <span class="font-bold">%s</span></div>',
            $counts['passed'],
            $counts['failed'],
            $counts['skipped'],
            $counts['errored'],
            $highest === null ? '—' : strtoupper($highest->value),
        ));
        render('<div class="mx-1 text-gray-500">──────────────────────────────────────────</div>');
    }

    /**
     * @param  array<int, Finding>  $findings
     */
    private function renderCheckRow(string $checkId, CheckStatus $status, array $findings, ScanResult $result): void
    {
        switch ($status) {
            case CheckStatus::Passed:
                render(sprintf(
                    '<div class="mx-3"><span class="bg-green-600 text-white w-10 text-center">PASS</span> <span>%s</span></div>',
                    htmlspecialchars($checkId, ENT_QUOTES),
                ));

                return;

            case CheckStatus::Skipped:
                render(sprintf(
                    '<div class="mx-3"><span class="bg-gray-500 text-white w-10 text-center">SKIP</span> <span class="text-gray-500">%s</span> <span class="text-gray-400">(%s)</span></div>',
                    htmlspecialchars($checkId, ENT_QUOTES),
                    htmlspecialchars($result->skipReasonOf($checkId) ?? 'unknown', ENT_QUOTES),
                ));

                return;

            case CheckStatus::Errored:
                render(sprintf(
                    '<div class="mx-3"><span class="bg-red-700 text-white w-10 text-center">ERROR</span> <span>%s</span></div>'
                    .'<div class="ml-14 text-red-400">└─ %s</div>',
                    htmlspecialchars($checkId, ENT_QUOTES),
                    htmlspecialchars($result->errorOf($checkId) ?? 'unknown', ENT_QUOTES),
                ));

                return;

            case CheckStatus::Failed:
                if ($findings === []) {
                    render(sprintf(
                        '<div class="mx-3"><span class="bg-red-500 text-white w-10 text-center">FAIL</span> <span>%s</span></div>',
                        htmlspecialchars($checkId, ENT_QUOTES),
                    ));

                    return;
                }

                // Find highest severity among findings for the header badge
                $highestSeverity = $findings[0]->severity;
                foreach ($findings as $f) {
                    if ($f->severity->rank() > $highestSeverity->rank()) {
                        $highestSeverity = $f->severity;
                    }
                }

                // Check header row with highest severity badge
                render(sprintf(
                    '<div class="mx-3">%s <span>%s</span></div>',
                    SeverityBadge::html($highestSeverity),
                    htmlspecialchars($checkId, ENT_QUOTES),
                ));

                // Each finding indented underneath
                $lastKey = array_key_last($findings);
                foreach ($findings as $i => $f) {
                    $connector = $i === $lastKey ? '└─' : '├─';
                    $location = '';
                    if ($f->file !== null) {
                        $loc = $f->file.($f->line !== null ? ':'.$f->line : '');
                        $location = sprintf(' <span class="text-gray-500">(%s)</span>', htmlspecialchars($loc, ENT_QUOTES));
                    }
                    render(sprintf(
                        '<div class="ml-14"><span class="text-gray-400">%s</span> <span>%s</span>%s</div>',
                        $connector,
                        htmlspecialchars($f->message, ENT_QUOTES),
                        $location,
                    ));
                }

                return;
        }
    }

    private function renderPlain(ScanResult $result, OutputInterface $output): void
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
                CheckStatus::Failed => $this->renderPlainFailures($checkId, $findingsByCheck[$checkId] ?? []),
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
    private function renderPlainFailures(string $checkId, array $findings): string
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

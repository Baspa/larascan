<?php

declare(strict_types=1);

namespace Baspa\Larascan\Reporters;

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

        render('<div class="mx-1 my-1"><div class="bg-blue-500 text-white px-2 py-1 font-bold">larascan — security scan</div></div>');

        // Group findings per check for grouped display
        $findingsByCheck = [];
        foreach ($result->findings() as $f) {
            $findingsByCheck[$f->checkId][] = $f;
        }

        foreach ($result->statuses() as $checkId => $status) {
            match ($status) {
                CheckStatus::Passed => render(sprintf(
                    '<div class="ml-2"><span class="bg-green-500 text-white px-1">PASS</span> <span>%s</span></div>',
                    htmlspecialchars($checkId, ENT_QUOTES),
                )),
                CheckStatus::Skipped => render(sprintf(
                    '<div class="ml-2"><span class="bg-gray-400 text-black px-1">SKIP</span> <span class="text-gray-500">%s</span> <span class="text-gray-400">(%s)</span></div>',
                    htmlspecialchars($checkId, ENT_QUOTES),
                    htmlspecialchars($result->skipReasonOf($checkId) ?? 'unknown', ENT_QUOTES),
                )),
                CheckStatus::Errored => render(sprintf(
                    '<div class="ml-2"><span class="bg-red-700 text-white px-1">ERROR</span> <span>%s</span> <span class="text-red-400">— %s</span></div>',
                    htmlspecialchars($checkId, ENT_QUOTES),
                    htmlspecialchars($result->errorOf($checkId) ?? 'unknown', ENT_QUOTES),
                )),
                CheckStatus::Failed => $this->renderFailures($checkId, $findingsByCheck[$checkId] ?? []),
            };
        }

        $counts = $result->counts();
        $highest = $result->highestSeverity();
        $highestLabel = $highest === null ? '—' : strtoupper($highest->value);

        render(sprintf(
            '<div class="mt-1 mx-1"><div class="bg-blue-500 text-white px-2 py-1 font-bold">Report</div></div>'
            .'<div class="ml-2">Passed <span class="text-green-500 font-bold">%d</span>    '
            .'Failed <span class="text-red-500 font-bold">%d</span>    '
            .'Skipped <span class="text-gray-500 font-bold">%d</span>    '
            .'Errored <span class="text-red-700 font-bold">%d</span></div>'
            .'<div class="ml-2 text-gray-500">Highest severity: <span class="text-white">%s</span></div>',
            $counts['passed'],
            $counts['failed'],
            $counts['skipped'],
            $counts['errored'],
            $highestLabel,
        ));
    }

    /**
     * @param  array<int, Finding>  $findings
     */
    private function renderFailures(string $checkId, array $findings): void
    {
        if ($findings === []) {
            render(sprintf(
                '<div class="ml-2"><span class="bg-red-500 text-white px-1">FAIL</span> <span>%s</span></div>',
                htmlspecialchars($checkId, ENT_QUOTES),
            ));

            return;
        }

        foreach ($findings as $f) {
            render(sprintf(
                '<div class="ml-2">%s <span>%s</span></div><div class="ml-4 text-gray-400">└─ %s</div>',
                SeverityBadge::html($f->severity),
                htmlspecialchars($checkId, ENT_QUOTES),
                htmlspecialchars($f->message, ENT_QUOTES),
            ));
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

<?php

declare(strict_types=1);

namespace Baspa\Larascan\Reporters;

use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\CheckStatus;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ScanResult;
use Baspa\Larascan\Support\Severity;
use Symfony\Component\Console\Output\OutputInterface;

final class ConsoleReporter
{
    private const BAR_WIDTH = 20;

    public function render(ScanResult $result, OutputInterface $output, bool $onlyFailed = false): void
    {
        $output->writeln('');
        $output->writeln('<fg=cyan;options=bold>larascan</> security scan');
        $output->writeln('<fg=gray>════════════════════════════════════════════</>');
        $output->writeln('');

        // Pre-index findings per check
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

        // Render per-category sections
        foreach ($byCategory as $prefix => $checkIds) {
            if ($onlyFailed) {
                $checkIds = array_filter(
                    $checkIds,
                    fn (string $id) => in_array(
                        $result->statusOf($id),
                        [CheckStatus::Failed, CheckStatus::Errored],
                        true,
                    ),
                );
                if ($checkIds === []) {
                    continue;
                }
            }

            $cat = Category::tryFrom($prefix);
            $label = $cat?->label() ?? ucfirst($prefix);

            $output->writeln(sprintf('  <fg=cyan;options=bold>%s</>', $label));
            $output->writeln(sprintf('  <fg=gray>%s</>', str_repeat('─', mb_strlen($label))));

            foreach ($checkIds as $checkId) {
                $this->renderCheckRow(
                    $output,
                    $checkId,
                    $result->statusOf($checkId),
                    $findingsByCheck[$checkId] ?? [],
                    $result,
                );
            }
            $output->writeln('');
        }

        // Report Card — always uses the full unfiltered $byCategory for accurate stats
        $this->renderReportCard($output, $result, $byCategory);
    }

    /**
     * @param  array<int, Finding>  $findings
     */
    private function renderCheckRow(OutputInterface $output, string $checkId, ?CheckStatus $status, array $findings, ScanResult $result): void
    {
        switch ($status) {
            case CheckStatus::Passed:
                $output->writeln(sprintf('     <fg=green>✓</> %s', $checkId));

                return;

            case CheckStatus::Skipped:
                $output->writeln(sprintf(
                    '     <fg=yellow>⊘</> %-45s <fg=gray>%s</>',
                    $checkId,
                    'skipped — '.($result->skipReasonOf($checkId) ?? 'unknown'),
                ));

                return;

            case CheckStatus::Errored:
                $output->writeln(sprintf(
                    '     <fg=red;options=bold>!</> %-45s <fg=red>ERROR — %s</>',
                    $checkId,
                    $result->errorOf($checkId) ?? 'unknown',
                ));

                return;

            case CheckStatus::Failed:
                if ($findings === []) {
                    $output->writeln(sprintf('     <fg=red>✗</> %s <fg=red>FAILED</>', $checkId));

                    return;
                }

                // Find the highest severity to color the check-level glyph
                $highest = $findings[0]->severity;
                foreach ($findings as $f) {
                    if ($f->severity->rank() > $highest->rank()) {
                        $highest = $f->severity;
                    }
                }

                $output->writeln(sprintf(
                    '     %s %s',
                    $this->failedGlyphFor($highest),
                    $checkId,
                ));

                $lastKey = array_key_last($findings);
                foreach ($findings as $i => $f) {
                    $connector = $i === $lastKey ? '└─' : '├─';
                    $location = '';
                    if ($f->file !== null) {
                        $loc = $f->file.($f->line !== null ? ':'.$f->line : '');
                        $location = sprintf(' <fg=gray>(%s)</>', $loc);
                    }
                    $output->writeln(sprintf(
                        '        <fg=gray>%s</> %s %s%s',
                        $connector,
                        $this->severityLabel($f->severity),
                        $f->message,
                        $location,
                    ));
                }

                return;
        }
    }

    private function severityLabel(Severity $severity): string
    {
        // Slim text-only label, padded to 8 chars for clean column alignment.
        return match ($severity) {
            Severity::Critical => '<fg=red;options=bold>CRITICAL</>',
            Severity::High => '<fg=red>HIGH    </>',
            Severity::Medium => '<fg=yellow>MEDIUM  </>',
            Severity::Low => '<fg=blue>LOW     </>',
            Severity::Info => '<fg=gray>INFO    </>',
        };
    }

    private function failedGlyphFor(Severity $severity): string
    {
        return match ($severity) {
            Severity::Critical => '<fg=red;options=bold>✗</>',
            Severity::High => '<fg=red>✗</>',
            Severity::Medium => '<fg=yellow>✗</>',
            Severity::Low => '<fg=blue>✗</>',
            Severity::Info => '<fg=gray>✗</>',
        };
    }

    /**
     * @param  array<string, array<int, string>>  $byCategory
     */
    private function renderReportCard(OutputInterface $output, ScanResult $result, array $byCategory): void
    {
        $counts = $result->counts();
        $highest = $result->highestSeverity();

        $output->writeln('<fg=gray>════════════════════════════════════════════</>');
        $output->writeln('  <fg=cyan;options=bold>Report Card</>');
        $output->writeln('<fg=gray>════════════════════════════════════════════</>');
        $output->writeln('');

        // Per-category bars
        foreach ($byCategory as $prefix => $checkIds) {
            $cat = Category::tryFrom($prefix);
            $label = $cat?->label() ?? ucfirst($prefix);

            $catPassed = 0;
            $catTotal = 0;
            foreach ($checkIds as $id) {
                $status = $result->statusOf($id);
                if ($status === CheckStatus::Skipped) {
                    continue;  // don't count skips toward pass percentage
                }
                $catTotal++;
                if ($status === CheckStatus::Passed) {
                    $catPassed++;
                }
            }

            $pct = $catTotal === 0 ? 100 : (int) round(($catPassed / $catTotal) * 100);
            $filled = (int) round(($pct / 100) * self::BAR_WIDTH);
            $bar = str_repeat('█', $filled).str_repeat('░', self::BAR_WIDTH - $filled);

            $color = $pct >= 80 ? 'green' : ($pct >= 50 ? 'yellow' : 'red');

            $output->writeln(sprintf(
                '  %-24s <fg=%s>%s</> %3d%%   <fg=gray>(%d/%d)</>',
                $label,
                $color,
                $bar,
                $pct,
                $catPassed,
                $catTotal,
            ));
        }

        $output->writeln('');
        $output->writeln(sprintf(
            '  Total: <fg=green>%d passed</>   <fg=red>%d failed</>   <fg=yellow>%d skipped</>   <fg=red;options=bold>%d errored</>',
            $counts['passed'],
            $counts['failed'],
            $counts['skipped'],
            $counts['errored'],
        ));

        if ($highest !== null) {
            $output->writeln(sprintf(
                '  Highest severity: %s',
                $this->severityLabel($highest),
            ));
        }
        $output->writeln('');
    }
}

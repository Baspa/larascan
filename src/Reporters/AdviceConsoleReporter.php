<?php

declare(strict_types=1);

namespace Baspa\Larascan\Reporters;

use Baspa\Larascan\Support\AdviceRegistry;
use Baspa\Larascan\Support\AdviceResult;
use Baspa\Larascan\Support\AdviceStatus;
use Baspa\Larascan\Support\Category;
use Symfony\Component\Console\Output\OutputInterface;

final class AdviceConsoleReporter
{
    public function render(AdviceResult $result, AdviceRegistry $registry, OutputInterface $output): void
    {
        $output->writeln('');
        $output->writeln('<fg=cyan;options=bold>larascan</> security advise');
        $output->writeln('<fg=gray>════════════════════════════════════════════</>');
        $output->writeln('');

        if ($registry->all() === []) {
            $output->writeln('  <fg=gray>no advices configured</>');
            $output->writeln('');

            return;
        }

        $namesById = [];
        foreach ($registry->all() as $advice) {
            $namesById[$advice->id()] = $advice;
        }

        $surfacedByCategory = [];
        foreach ($result->outcomes() as $id => $outcome) {
            if ($outcome->status !== AdviceStatus::Surfaced) {
                continue;
            }
            $cat = ($namesById[$id] ?? null)?->category() ?? Category::Repo;
            $surfacedByCategory[$cat->value][] = $id;
        }

        if ($surfacedByCategory === []) {
            $output->writeln('  <fg=green>No advisories surfaced for this codebase.</>');
        }

        foreach ($surfacedByCategory as $prefix => $ids) {
            $cat = Category::tryFrom($prefix);
            $label = $cat !== null ? $cat->label() : ucfirst($prefix);
            $output->writeln(sprintf('  <fg=cyan;options=bold>%s</>', $label));
            $output->writeln(sprintf('  <fg=gray>%s</>', str_repeat('─', mb_strlen($label))));

            foreach ($ids as $id) {
                $outcome = $result->outcomeOf($id);
                if ($outcome === null) {
                    continue;
                }
                $output->writeln(sprintf('     <fg=yellow>⚑</> %s', $id));
                if ($outcome->summary !== '') {
                    $output->writeln(sprintf('        <fg=gray>└─</> %s', $outcome->summary));
                }
                $lastKey = array_key_last($outcome->evidence);
                foreach ($outcome->evidence as $i => $evidence) {
                    $connector = $i === $lastKey ? '└─' : '├─';
                    $location = '';
                    if ($evidence->file !== null) {
                        $loc = $evidence->file.($evidence->line !== null ? ':'.$evidence->line : '');
                        $location = sprintf(' <fg=gray>(%s)</>', $loc);
                    }
                    $output->writeln(sprintf(
                        '           <fg=gray>%s</> %s%s',
                        $connector,
                        $evidence->message,
                        $location,
                    ));
                }
            }
            $output->writeln('');
        }

        $counts = $result->counts();
        $output->writeln('<fg=gray>════════════════════════════════════════════</>');
        $output->writeln(sprintf(
            '  <fg=yellow>%d surfaced</>   <fg=gray>%d not surfaced</>   <fg=yellow>%d skipped</>   <fg=red>%d errored</>',
            $counts['surfaced'], $counts['not_surfaced'], $counts['skipped'], $counts['errored'],
        ));
        $output->writeln('');
        $output->writeln('  <fg=gray>Manual security review: see</> <fg=cyan>docs/manual-security-checklist.md</>');
        $output->writeln('');
    }
}

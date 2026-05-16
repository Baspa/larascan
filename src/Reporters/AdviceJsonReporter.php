<?php

declare(strict_types=1);

namespace Baspa\Larascan\Reporters;

use Baspa\Larascan\Support\AdviceRegistry;
use Baspa\Larascan\Support\AdviceResult;
use Symfony\Component\Console\Output\OutputInterface;

final class AdviceJsonReporter
{
    private const VERSION = '2.1.0';

    public function render(AdviceResult $result, AdviceRegistry $registry, OutputInterface $output): void
    {
        $namesById = [];
        foreach ($registry->all() as $advice) {
            $namesById[$advice->id()] = $advice;
        }

        $advices = [];
        foreach ($result->outcomes() as $id => $outcome) {
            $advice = $namesById[$id] ?? null;
            $evidence = array_map(
                fn ($e) => [
                    'message' => $e->message,
                    'file' => $e->file,
                    'line' => $e->line,
                    'snippet' => $e->snippet,
                ],
                $outcome->evidence,
            );

            $advices[] = [
                'id' => $id,
                'category' => $advice?->category()->value,
                'status' => $outcome->status->value,
                'name' => $advice?->name(),
                'summary' => $outcome->summary,
                'skip_reason' => $outcome->skipReason,
                'evidence' => $evidence,
            ];
        }

        $payload = [
            'version' => self::VERSION,
            'summary' => $result->counts(),
            'advices' => $advices,
        ];

        $output->writeln((string) json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }
}

<?php

declare(strict_types=1);

namespace Baspa\Larascan\Reporters;

use Baspa\Larascan\Contracts\Check;
use Baspa\Larascan\Support\CheckRegistry;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ScanResult;
use Composer\InstalledVersions;
use RuntimeException;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

/**
 * Renders a SARIF 2.1.0 report suitable for GitHub Code Scanning
 * (github/codeql-action/upload-sarif). Results are failures only, so
 * unlike the other reporters there is no onlyFailed switch.
 */
final class SarifReporter
{
    private const SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';

    private const INFORMATION_URI = 'https://github.com/baspa/larascan';

    public function __construct(
        private readonly CheckRegistry $registry,
    ) {}

    public function render(ScanResult $result, OutputInterface $output): void
    {
        $checksById = [];
        foreach ($this->registry->all() as $check) {
            $checksById[$check->id()] = $check;
        }

        // Only checks that produced at least one finding become rules.
        /** @var array<int, array<string, mixed>> $rules */
        $rules = [];
        /** @var array<string, int> $ruleIndexById */
        $ruleIndexById = [];
        foreach ($result->findings() as $finding) {
            if (isset($ruleIndexById[$finding->checkId])) {
                continue;
            }
            $check = $checksById[$finding->checkId] ?? null;
            $ruleIndexById[$finding->checkId] = count($rules);
            $rules[] = $check !== null
                ? $this->buildRule($check)
                : ['id' => $finding->checkId];
        }

        $results = array_map(
            fn (Finding $f): array => $this->buildResult($f, $ruleIndexById),
            $result->findings(),
        );

        $payload = [
            '$schema' => self::SCHEMA,
            'version' => '2.1.0',
            'runs' => [
                [
                    'tool' => [
                        'driver' => [
                            'name' => 'Larascan',
                            'informationUri' => self::INFORMATION_URI,
                            'version' => $this->toolVersion(),
                            'rules' => $rules,
                        ],
                    ],
                    'results' => $results,
                ],
            ],
        ];

        // Messages and snippets embed scanned-file content, which may not be
        // valid UTF-8; substitute rather than have json_encode fail outright.
        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);

        if ($json === false) {
            throw new RuntimeException('Failed to encode SARIF report: '.json_last_error_msg());
        }

        // OUTPUT_RAW: scanned snippets may contain console-style tags
        // (<error>, <info>, ...) that the formatter would otherwise strip.
        $output->writeln($json, OutputInterface::OUTPUT_RAW);
    }

    /**
     * @return array<string, mixed>
     */
    private function buildRule(Check $check): array
    {
        return [
            'id' => $check->id(),
            'name' => $check->name(),
            'shortDescription' => ['text' => $check->name()],
            'helpUri' => $check->docsUrl(),
            'defaultConfiguration' => ['level' => $check->severity()->sarifLevel()],
            'properties' => [
                'security-severity' => $check->severity()->securitySeverityScore(),
                'tags' => ['security', $check->category()->value],
            ],
        ];
    }

    /**
     * @param  array<string, int>  $ruleIndexById
     * @return array<string, mixed>
     */
    private function buildResult(Finding $finding, array $ruleIndexById): array
    {
        // GitHub drops results without a location, so findings that are not
        // tied to a repository file (config-level checks, or paths outside
        // base_path()) get a synthesized anchor.
        $uri = $this->normalizeUri($finding->file);
        $synthesized = $uri === null;

        $region = ['startLine' => $synthesized ? 1 : ($finding->line ?? 1)];
        if ($finding->snippet !== null) {
            $region['snippet'] = ['text' => $finding->snippet];
        }

        $result = [
            'ruleId' => $finding->checkId,
            'ruleIndex' => $ruleIndexById[$finding->checkId],
            'level' => $finding->severity->sarifLevel(),
            'message' => ['text' => $finding->message],
            'locations' => [
                [
                    'physicalLocation' => [
                        'artifactLocation' => ['uri' => $uri ?? 'composer.json'],
                        'region' => $region,
                    ],
                ],
            ],
        ];

        if ($synthesized) {
            $result['properties'] = ['larascan' => ['synthesizedLocation' => true]];
        }

        return $result;
    }

    /**
     * Returns a repository-relative URI, or null when the finding has no
     * mappable file (no file at all, or a path outside base_path()).
     */
    private function normalizeUri(?string $file): ?string
    {
        if ($file === null || $file === '') {
            return null;
        }

        $file = str_replace('\\', '/', $file);
        $base = str_replace('\\', '/', base_path());

        if ($base !== '' && str_starts_with($file, $base.'/')) {
            $file = substr($file, strlen($base) + 1);
        }

        // Still absolute => outside base_path(); Code Scanning cannot map it, so fall back to the synthesized anchor.
        if (preg_match('#^(?:[A-Za-z]:)?/#', $file) === 1) {
            return null;
        }

        return $file;
    }

    private function toolVersion(): string
    {
        try {
            return InstalledVersions::getPrettyVersion('baspa/larascan') ?? 'dev';
        } catch (Throwable) {
            return 'dev';
        }
    }
}

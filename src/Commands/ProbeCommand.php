<?php

declare(strict_types=1);

namespace Baspa\Larascan\Commands;

use Baspa\Larascan\Prober;
use Baspa\Larascan\Reporters\ConsoleReporter;
use Baspa\Larascan\Reporters\JsonReporter;
use Baspa\Larascan\Support\AgentDetector;
use Baspa\Larascan\Support\ProbeContextFactory;
use Baspa\Larascan\Support\ProbeRegistry;
use Baspa\Larascan\Support\ScanResult;
use Baspa\Larascan\Support\Severity;
use Illuminate\Console\Command;
use Illuminate\Http\Client\ConnectionException;
use Symfony\Component\Console\Output\OutputInterface;

class ProbeCommand extends Command
{
    protected $signature = 'larascan:probe
        {--url= : URL to probe (defaults to larascan.probe.url, then app.url)}
        {--fail-on= : Severity threshold for non-zero exit}
        {--probe=* : Filter probes by ID pattern (e.g. probe.cookie*)}
        {--timeout= : Request timeout in seconds}
        {--insecure : Skip TLS certificate verification}
        {--ignore-errors : Force exit 0 even on probe errors}
        {--only-failed : Hide passed and skipped probes}
        {--format= : human (default) or json}';

    protected $description = 'Probe a running app with one HTTP request and verify response headers/cookies';

    public function handle(Prober $prober, ConsoleReporter $reporter): int
    {
        $failOnOption = $this->option('fail-on');
        $failOnConfig = config('larascan.fail_on');
        $failOnRaw = match (true) {
            is_string($failOnOption) && $failOnOption !== '' => $failOnOption,
            is_string($failOnConfig) && $failOnConfig !== '' => $failOnConfig,
            default => 'high',
        };
        $failOn = Severity::tryFrom($failOnRaw);
        if ($failOn === null) {
            $this->error("Invalid --fail-on value: {$failOnRaw}");

            return 2;
        }

        $formatOption = $this->option('format');
        $format = is_string($formatOption) && $formatOption !== ''
            ? strtolower($formatOption)
            : $this->autoFormat();
        if (! in_array($format, ['human', 'json'], true)) {
            $this->error("Invalid --format value: {$format}");

            return 2;
        }

        $url = $this->resolveUrl();
        if ($url === null) {
            $this->error('No URL to probe — pass --url, set larascan.probe.url (LARASCAN_PROBE_URL), or configure app.url.');

            return 2;
        }

        $timeout = $this->resolveTimeout();
        $insecure = (bool) $this->option('insecure');
        $onlyFailed = (bool) $this->option('only-failed');

        /** @var array<int, string> $patterns */
        $patterns = (array) $this->option('probe');

        $this->line("Probing {$url} — one GET request will be sent.");

        // Scope the prober to the matching probes so a filtered run only ever
        // probes (and reports) the requested ids.
        $prober = $patterns !== [] ? $this->scopedProber($prober, $patterns) : $prober;
        $enabledIds = array_map(fn ($p) => $p->id(), $prober->registry()->enabled());

        $factory = new ProbeContextFactory;

        try {
            $context = $factory->fromUrl($url, $timeout, $insecure);
        } catch (ConnectionException $e) {
            $result = $this->erroredResult($enabledIds, $e);
            $this->renderFormat($format, $result, $this->output, $onlyFailed, $reporter);

            if ($this->option('ignore-errors')) {
                return 0;
            }

            return 2;
        }

        $result = $prober->probe($context);

        $this->renderFormat($format, $result, $this->output, $onlyFailed, $reporter);

        $counts = $result->counts();
        if ($counts['errored'] > 0 && ! $this->option('ignore-errors')) {
            return 2;
        }

        $highest = $result->highestSeverity();
        if ($highest !== null && $highest->isAtLeast($failOn)) {
            return 1;
        }

        return 0;
    }

    private function resolveUrl(): ?string
    {
        $option = $this->option('url');
        $configUrl = config('larascan.probe.url');
        $appUrl = config('app.url');

        $raw = match (true) {
            is_string($option) && $option !== '' => $option,
            is_string($configUrl) && $configUrl !== '' => $configUrl,
            is_string($appUrl) && $appUrl !== '' => $appUrl,
            default => null,
        };

        if ($raw === null) {
            return null;
        }

        $scheme = parse_url($raw, PHP_URL_SCHEME);
        $host = parse_url($raw, PHP_URL_HOST);
        if (! is_string($scheme) || $scheme === '' || ! is_string($host) || $host === '') {
            return null;
        }

        return $raw;
    }

    private function resolveTimeout(): int
    {
        $option = $this->option('timeout');
        if (is_string($option) && $option !== '' && ctype_digit($option)) {
            return (int) $option;
        }

        $config = config('larascan.probe.timeout');

        return is_int($config) ? $config : 5;
    }

    /**
     * Build a Prober scoped to only the probes matching the --probe patterns.
     *
     * @param  array<int, string>  $patterns
     */
    private function scopedProber(Prober $prober, array $patterns): Prober
    {
        // Carry the same probe config so a probe disabled via
        // larascan.probe.probes.*.enabled stays disabled even when its id
        // matches a --probe pattern (consistent with the unscoped path).
        /** @var array<string, array{enabled?: bool}> $config */
        $config = config('larascan.probe.probes', []);
        $registry = new ProbeRegistry($config);
        foreach ($prober->registry()->matching($patterns) as $probe) {
            $registry->register($probe);
        }

        return new Prober($registry);
    }

    /**
     * Record every enabled probe id as errored so the report still renders
     * after a connection failure.
     *
     * @param  array<int, string>  $ids
     */
    private function erroredResult(array $ids, ConnectionException $e): ScanResult
    {
        $result = new ScanResult;
        foreach ($ids as $id) {
            $result = $result->recordError($id, $e);
        }

        return $result;
    }

    private function renderFormat(string $format, ScanResult $result, OutputInterface $output, bool $onlyFailed, ConsoleReporter $console): void
    {
        match ($format) {
            'json' => (new JsonReporter)->render($result, $output, onlyFailed: $onlyFailed),
            default => $console->render($result, $output, onlyFailed: $onlyFailed),
        };
    }

    private function autoFormat(): string
    {
        if (AgentDetector::isAgentRun()) {
            return 'json';
        }

        return 'human';
    }
}

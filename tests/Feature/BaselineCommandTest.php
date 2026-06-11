<?php

declare(strict_types=1);
use Baspa\Larascan\Contracts\Check;
use Baspa\Larascan\Larascan;
use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\CheckRegistry;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;

final class BaselineThrowingCheck extends AbstractCheck
{
    public function id(): string
    {
        return 'config.boom';
    }

    public function category(): Category
    {
        return Category::Config;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'always errors';
    }

    /** @return iterable<Finding> */
    public function run(): iterable
    {
        throw new RuntimeException('check exploded');
    }
}

beforeEach(function () {
    $this->baselinePath = sys_get_temp_dir().'/larascan-baseline-cmd-'.uniqid().'.json';
});

afterEach(function () {
    /** @var string $path */
    $path = $this->baselinePath;
    if (is_file($path)) {
        unlink($path);
    }
});

it('writes current findings to the baseline file and exits 0', function () {
    // Force a known failing check: APP_DEBUG=true in production is Critical.
    config()->set('app.env', 'production');
    config()->set('app.debug', true);

    $this->artisan('larascan:baseline', ['--baseline' => $this->baselinePath])
        ->expectsOutputToContain('Baseline written to '.$this->baselinePath)
        ->assertExitCode(0);

    expect(is_file($this->baselinePath))->toBeTrue();

    $decoded = json_decode((string) file_get_contents($this->baselinePath), true);

    expect($decoded['version'])->toBe(1)
        ->and($decoded['generated_at'])->toBeString()
        ->and($decoded['findings'])->toBeArray()->not->toBeEmpty();

    $checks = array_column($decoded['findings'], 'check');
    expect($checks)->toContain('config.app-debug');

    foreach ($decoded['findings'] as $entry) {
        expect($entry)->toHaveKeys(['check', 'file', 'message', 'severity', 'count'])
            ->and($entry['count'])->toBeGreaterThanOrEqual(1);
    }
});

it('writes an empty baseline when there are no findings', function () {
    // Disable every registered check so the scan yields zero findings. The
    // registry singleton caches config, so rebuild it after the change.
    $ids = array_map(
        fn (Check $c) => $c->id(),
        app(CheckRegistry::class)->all(),
    );
    config()->set('larascan.checks', array_fill_keys($ids, ['enabled' => false]));
    app()->forgetInstance(CheckRegistry::class);
    app()->forgetInstance(Larascan::class);

    $this->artisan('larascan:baseline', ['--baseline' => $this->baselinePath])
        ->expectsOutputToContain('0 findings across 0 checks')
        ->assertExitCode(0);

    $decoded = json_decode((string) file_get_contents($this->baselinePath), true);

    expect($decoded['version'])->toBe(1)
        ->and($decoded['findings'])->toBe([]);
});

it('warns about a check that errored and still writes the baseline', function () {
    // Replace the orchestrator with one whose only check throws, so the
    // per-errored-check warning loop runs.
    $registry = new CheckRegistry;
    $registry->register(new BaselineThrowingCheck);
    app()->instance(Larascan::class, new Larascan($registry));

    $this->artisan('larascan:baseline', ['--baseline' => $this->baselinePath])
        ->expectsOutputToContain('Check config.boom errored — its findings are not in the baseline')
        ->assertExitCode(0);

    // The errored check produced no findings, so the baseline is empty.
    $decoded = json_decode((string) file_get_contents($this->baselinePath), true);
    expect($decoded['findings'])->toBe([]);
});

it('falls back to the configured baseline path when no flag is given', function () {
    config()->set('app.env', 'production');
    config()->set('app.debug', true);
    config()->set('larascan.baseline', $this->baselinePath);

    $this->artisan('larascan:baseline')
        ->expectsOutputToContain($this->baselinePath)
        ->assertExitCode(0);

    expect(is_file($this->baselinePath))->toBeTrue();
});

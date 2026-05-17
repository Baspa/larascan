<?php

declare(strict_types=1);

use Baspa\Larascan\Advices\Dependencies\OutdatedPackagesAdvice;
use Baspa\Larascan\Support\AdviceStatus;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Tools\ComposerOutdatedRunner;
use Baspa\Larascan\Tools\NpmOutdatedRunner;

it('exposes correct metadata', function () {
    $advice = new OutdatedPackagesAdvice(
        composer: new ComposerOutdatedRunner('/nonexistent', 'composer'),
        npm: new NpmOutdatedRunner('/nonexistent', 'npm'),
    );

    expect($advice->id())->toBe('advise.outdated-packages')
        ->and($advice->category())->toBe(Category::Dependencies);
});

it('is skipped when neither composer nor npm is available', function () {
    $advice = new OutdatedPackagesAdvice(
        composer: new ComposerOutdatedRunner('/nonexistent', 'composer'),
        npm: new NpmOutdatedRunner('/nonexistent', 'npm'),
    );

    $outcome = $advice->run();
    expect($outcome->status)->toBe(AdviceStatus::Skipped);
});

it('does not surface when composer reports no outdated packages', function () {
    $tmpDir = sys_get_temp_dir().'/larascan-outdated-test-'.uniqid();
    mkdir($tmpDir);
    file_put_contents($tmpDir.'/composer.json', '{}');

    $composer = new class($tmpDir) extends ComposerOutdatedRunner
    {
        public function __construct(string $dir)
        {
            parent::__construct($dir, 'composer');
        }

        public function run(): array
        {
            return [];
        }
    };
    $npm = new NpmOutdatedRunner('/nonexistent', 'npm');

    $advice = new OutdatedPackagesAdvice($composer, $npm);
    $outcome = $advice->run();

    expect($outcome->status)->toBe(AdviceStatus::NotSurfaced);
    @unlink($tmpDir.'/composer.json');
    @rmdir($tmpDir);
});

it('surfaces with evidence when composer reports outdated packages', function () {
    $composer = new class extends ComposerOutdatedRunner
    {
        public function __construct()
        {
            parent::__construct('/dev/null', 'composer');
        }

        public function isAvailable(): bool
        {
            return true;
        }

        public function run(): array
        {
            return [
                ['name' => 'pkg/a', 'current' => '1.0.0', 'latest' => '2.0.0', 'status' => 'update-possible'],
                ['name' => 'pkg/b', 'current' => '1.0.0', 'latest' => '1.1.0', 'status' => 'update-possible'],
            ];
        }
    };
    $npm = new NpmOutdatedRunner('/nonexistent', 'npm');

    $outcome = (new OutdatedPackagesAdvice($composer, $npm))->run();

    expect($outcome->status)->toBe(AdviceStatus::Surfaced)
        ->and($outcome->evidence)->toHaveCount(2)
        ->and($outcome->summary)->toContain('outdated');
});

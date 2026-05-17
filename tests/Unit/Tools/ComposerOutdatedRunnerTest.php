<?php

declare(strict_types=1);

use Baspa\Larascan\Tools\ComposerOutdatedRunner;

beforeEach(function () {
    $this->tmpDir = sys_get_temp_dir().'/larascan-composer-outdated-'.uniqid();
    mkdir($this->tmpDir, recursive: true);
});

afterEach(function () {
    if (is_file($this->tmpDir.'/composer.json')) {
        unlink($this->tmpDir.'/composer.json');
    }
    if (is_dir($this->tmpDir)) {
        @rmdir($this->tmpDir);
    }
});

it('is unavailable when composer.json is missing', function () {
    $runner = new ComposerOutdatedRunner(workingDir: $this->tmpDir, binary: 'composer');
    expect($runner->isAvailable())->toBeFalse();
});

it('is available when composer.json exists and binary is on PATH', function () {
    file_put_contents($this->tmpDir.'/composer.json', '{}');
    $runner = new ComposerOutdatedRunner(workingDir: $this->tmpDir, binary: basename(PHP_BINARY));
    expect($runner->isAvailable())->toBeTrue();
});

it('is unavailable when binary is not on PATH', function () {
    file_put_contents($this->tmpDir.'/composer.json', '{}');
    $runner = new ComposerOutdatedRunner(workingDir: $this->tmpDir, binary: 'nonexistent-binary-xyz');
    expect($runner->isAvailable())->toBeFalse();
});

it('parses composer outdated JSON output', function () {
    $json = json_encode([
        'installed' => [
            ['name' => 'pkg/a', 'version' => '1.0.0', 'latest' => '2.0.0', 'latest-status' => 'update-possible'],
            ['name' => 'pkg/b', 'version' => '1.0.0', 'latest' => '1.1.0', 'latest-status' => 'update-possible'],
        ],
    ]);

    $entries = ComposerOutdatedRunner::parse((string) $json);

    expect($entries)->toHaveCount(2)
        ->and($entries[0]['name'])->toBe('pkg/a')
        ->and($entries[0]['current'])->toBe('1.0.0')
        ->and($entries[0]['latest'])->toBe('2.0.0');
});

it('returns empty array on malformed JSON', function () {
    expect(ComposerOutdatedRunner::parse('not json'))->toBe([]);
});

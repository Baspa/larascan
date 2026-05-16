<?php

declare(strict_types=1);

use Baspa\Larascan\Tools\NpmOutdatedRunner;

beforeEach(function () {
    $this->tmpDir = sys_get_temp_dir().'/larascan-npm-outdated-'.uniqid();
    mkdir($this->tmpDir, recursive: true);
});

afterEach(function () {
    if (is_file($this->tmpDir.'/package.json')) {
        unlink($this->tmpDir.'/package.json');
    }
    if (is_dir($this->tmpDir)) {
        @rmdir($this->tmpDir);
    }
});

it('is unavailable when package.json is missing', function () {
    $runner = new NpmOutdatedRunner(workingDir: $this->tmpDir, binary: 'npm');
    expect($runner->isAvailable())->toBeFalse();
});

it('is available when package.json exists and binary is on PATH', function () {
    file_put_contents($this->tmpDir.'/package.json', '{}');
    $runner = new NpmOutdatedRunner(workingDir: $this->tmpDir, binary: basename(PHP_BINARY));
    expect($runner->isAvailable())->toBeTrue();
});

it('is unavailable when binary is not on PATH', function () {
    file_put_contents($this->tmpDir.'/package.json', '{}');
    $runner = new NpmOutdatedRunner(workingDir: $this->tmpDir, binary: 'nonexistent-binary-xyz');
    expect($runner->isAvailable())->toBeFalse();
});

it('parses npm outdated JSON output', function () {
    $json = json_encode([
        'pkg-a' => ['current' => '1.0.0', 'wanted' => '1.0.5', 'latest' => '2.0.0'],
        'pkg-b' => ['current' => '0.5.0', 'wanted' => '0.5.1', 'latest' => '0.5.1'],
    ]);

    $entries = NpmOutdatedRunner::parse((string) $json);

    expect($entries)->toHaveCount(2)
        ->and($entries[0]['name'])->toBe('pkg-a')
        ->and($entries[0]['current'])->toBe('1.0.0')
        ->and($entries[0]['latest'])->toBe('2.0.0');
});

it('returns empty array on empty output', function () {
    expect(NpmOutdatedRunner::parse(''))->toBe([])
        ->and(NpmOutdatedRunner::parse('not json'))->toBe([]);
});

<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Dependencies\MinimumStabilityDevCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

function minimumStabilityRecursiveRemove(string $dir): void
{
    if (! is_dir($dir)) {
        return;
    }
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );
    foreach ($it as $f) {
        $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
    }
    rmdir($dir);
}

beforeEach(function () {
    $this->tmpDir = sys_get_temp_dir().'/larascan-min-stability-'.uniqid();
    mkdir($this->tmpDir, recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    minimumStabilityRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new MinimumStabilityDevCheck($this->tmpDir);

    expect($check->id())->toBe('dependencies.minimum-stability-dev')
        ->and($check->category())->toBe(Category::Dependencies)
        ->and($check->severity())->toBe(Severity::Medium);
});

it('is not applicable when composer.json is missing', function () {
    $check = new MinimumStabilityDevCheck($this->tmpDir);

    expect($check->isApplicable())->toBeFalse();
});

it('is applicable when composer.json is present', function () {
    file_put_contents($this->tmpDir.'/composer.json', json_encode(['name' => 'foo/bar']));

    $check = new MinimumStabilityDevCheck($this->tmpDir);

    expect($check->isApplicable())->toBeTrue();
});

it('passes when minimum-stability is stable', function () {
    file_put_contents($this->tmpDir.'/composer.json', json_encode([
        'name' => 'foo/bar',
        'minimum-stability' => 'stable',
    ]));

    $check = new MinimumStabilityDevCheck($this->tmpDir);

    expect(iterator_to_array($check->run()))->toBeEmpty();
});

it('passes when minimum-stability is dev but prefer-stable is true', function () {
    file_put_contents($this->tmpDir.'/composer.json', json_encode([
        'name' => 'foo/bar',
        'minimum-stability' => 'dev',
        'prefer-stable' => true,
    ]));

    $check = new MinimumStabilityDevCheck($this->tmpDir);

    expect(iterator_to_array($check->run()))->toBeEmpty();
});

it('fails when minimum-stability is dev without prefer-stable', function () {
    file_put_contents($this->tmpDir.'/composer.json', json_encode([
        'name' => 'foo/bar',
        'minimum-stability' => 'dev',
    ]));

    $check = new MinimumStabilityDevCheck($this->tmpDir);
    $findings = iterator_to_array($check->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->checkId)->toBe('dependencies.minimum-stability-dev')
        ->and($findings[0]->message)->toContain('minimum-stability')
        ->and($findings[0]->message)->toContain('prefer-stable');
});

it('fails when minimum-stability is dev and prefer-stable is false', function () {
    file_put_contents($this->tmpDir.'/composer.json', json_encode([
        'name' => 'foo/bar',
        'minimum-stability' => 'dev',
        'prefer-stable' => false,
    ]));

    $check = new MinimumStabilityDevCheck($this->tmpDir);
    $findings = iterator_to_array($check->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium);
});

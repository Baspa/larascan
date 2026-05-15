<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Repo\DependabotCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

function dependabotRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-dependabot-'.uniqid();
    mkdir($this->tmpDir, recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    dependabotRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new DependabotCheck($this->tmpDir);

    expect($check->id())->toBe('repo.dependabot')
        ->and($check->category())->toBe(Category::Repo)
        ->and($check->severity())->toBe(Severity::Low);
});

it('is not applicable when .github directory is missing', function () {
    $check = new DependabotCheck($this->tmpDir);

    expect($check->isApplicable())->toBeFalse();
});

it('passes when .github/dependabot.yml exists', function () {
    mkdir($this->tmpDir.'/.github', recursive: true);
    file_put_contents($this->tmpDir.'/.github/dependabot.yml', "version: 2\n");

    $check = new DependabotCheck($this->tmpDir);
    $findings = iterator_to_array($check->run());

    expect($findings)->toBeEmpty();
});

it('fails when .github exists but no dependabot config is present', function () {
    mkdir($this->tmpDir.'/.github', recursive: true);

    $check = new DependabotCheck($this->tmpDir);
    $findings = iterator_to_array($check->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Low)
        ->and($findings[0]->checkId)->toBe('repo.dependabot')
        ->and($findings[0]->message)->toContain('dependabot');
});

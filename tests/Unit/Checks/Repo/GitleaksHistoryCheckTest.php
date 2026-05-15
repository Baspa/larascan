<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Repo\GitleaksHistoryCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Symfony\Component\Process\Process;

function gitleaksRunGit(string $dir, array $args): void
{
    $p = new Process(array_merge(['git'], $args), $dir);
    $p->run();
}

function gitleaksInitRepo(string $dir): void
{
    gitleaksRunGit($dir, ['init', '--quiet']);
    gitleaksRunGit($dir, ['config', 'user.email', 't@t']);
    gitleaksRunGit($dir, ['config', 'user.name', 't']);
    gitleaksRunGit($dir, ['config', 'commit.gpgsign', 'false']);
}

function gitleaksRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-gitleaks-'.uniqid();
    mkdir($this->tmpDir);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    gitleaksRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new GitleaksHistoryCheck($this->tmpDir);

    expect($check->id())->toBe('repo.gitleaks-history')
        ->and($check->category())->toBe(Category::Repo)
        ->and($check->severity())->toBe(Severity::High);
});

it('is not applicable when .git directory is missing', function () {
    $check = new GitleaksHistoryCheck($this->tmpDir);

    expect($check->isApplicable())->toBeFalse();
});

it('passes when commits do not contain known secret patterns', function () {
    gitleaksInitRepo($this->tmpDir);
    file_put_contents("{$this->tmpDir}/README.md", "Hello world\n");
    gitleaksRunGit($this->tmpDir, ['add', 'README.md']);
    gitleaksRunGit($this->tmpDir, ['commit', '-m', 'init', '--quiet']);

    $findings = iterator_to_array((new GitleaksHistoryCheck($this->tmpDir))->run());

    expect($findings)->toBeEmpty();
});

it('fails when a commit contains an AWS access key', function () {
    gitleaksInitRepo($this->tmpDir);
    file_put_contents("{$this->tmpDir}/config.txt", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n");
    gitleaksRunGit($this->tmpDir, ['add', 'config.txt']);
    gitleaksRunGit($this->tmpDir, ['commit', '-m', 'leak', '--quiet']);

    $findings = iterator_to_array((new GitleaksHistoryCheck($this->tmpDir))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('repo.gitleaks-history')
        ->and($findings[0]->message)->toContain('AWS');
});

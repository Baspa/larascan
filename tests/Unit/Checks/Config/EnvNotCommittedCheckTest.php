<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Config\EnvNotCommittedCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Symfony\Component\Process\Process;

function envNotCommittedRunGit(string $dir, array $args): void
{
    $p = new Process(array_merge(['git'], $args), $dir);
    $p->run();
}

function envNotCommittedInitRepo(string $dir): void
{
    envNotCommittedRunGit($dir, ['init', '--quiet']);
    envNotCommittedRunGit($dir, ['config', 'user.email', 't@t']);
    envNotCommittedRunGit($dir, ['config', 'user.name', 't']);
    envNotCommittedRunGit($dir, ['config', 'commit.gpgsign', 'false']);
}

function envNotCommittedRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-env-'.uniqid();
    mkdir($this->tmpDir);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    envNotCommittedRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new EnvNotCommittedCheck($this->tmpDir);

    expect($check->id())->toBe('config.env-not-committed')
        ->and($check->category())->toBe(Category::Config)
        ->and($check->severity())->toBe(Severity::Critical);
});

it('is skipped outside a git working tree', function () {
    $check = new EnvNotCommittedCheck($this->tmpDir);
    expect($check->isApplicable())->toBeFalse();
});

it('passes when .env is gitignored and never committed', function () {
    envNotCommittedInitRepo($this->tmpDir);
    file_put_contents("{$this->tmpDir}/.gitignore", ".env\n");
    envNotCommittedRunGit($this->tmpDir, ['add', '.gitignore']);
    envNotCommittedRunGit($this->tmpDir, ['commit', '-m', 'init', '--quiet']);

    $findings = iterator_to_array((new EnvNotCommittedCheck($this->tmpDir))->run());
    expect($findings)->toBeEmpty();
});

it('fails when .env is missing from .gitignore', function () {
    envNotCommittedInitRepo($this->tmpDir);
    file_put_contents("{$this->tmpDir}/.gitignore", "vendor/\n");
    envNotCommittedRunGit($this->tmpDir, ['add', '.gitignore']);
    envNotCommittedRunGit($this->tmpDir, ['commit', '-m', 'init', '--quiet']);

    $findings = iterator_to_array((new EnvNotCommittedCheck($this->tmpDir))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toContain('.gitignore');
});

it('fails when .env exists in git history', function () {
    envNotCommittedInitRepo($this->tmpDir);
    file_put_contents("{$this->tmpDir}/.gitignore", ".env\n");
    file_put_contents("{$this->tmpDir}/.env", "APP_KEY=secret\n");
    envNotCommittedRunGit($this->tmpDir, ['add', '-f', '.env', '.gitignore']);
    envNotCommittedRunGit($this->tmpDir, ['commit', '-m', 'init', '--quiet']);

    $findings = iterator_to_array((new EnvNotCommittedCheck($this->tmpDir))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toContain('committed');
});

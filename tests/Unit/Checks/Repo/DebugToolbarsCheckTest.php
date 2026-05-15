<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Repo\DebugToolbarsCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

function debugToolbarsRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-debug-toolbars-'.uniqid();
    mkdir($this->tmpDir, recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    debugToolbarsRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new DebugToolbarsCheck($this->tmpDir);

    expect($check->id())->toBe('repo.debug-toolbars')
        ->and($check->category())->toBe(Category::Repo)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when composer.json has no debug tools', function () {
    file_put_contents($this->tmpDir.'/composer.json', json_encode([
        'name' => 'example/app',
        'require' => [
            'php' => '^8.2',
            'laravel/framework' => '^11.0',
        ],
    ]));

    $check = new DebugToolbarsCheck($this->tmpDir);
    $findings = iterator_to_array($check->run());

    expect($findings)->toBeEmpty();
});

it('passes when debugbar is in require-dev', function () {
    file_put_contents($this->tmpDir.'/composer.json', json_encode([
        'name' => 'example/app',
        'require' => [
            'php' => '^8.2',
        ],
        'require-dev' => [
            'barryvdh/laravel-debugbar' => '^3.0',
        ],
    ]));

    $check = new DebugToolbarsCheck($this->tmpDir);
    $findings = iterator_to_array($check->run());

    expect($findings)->toBeEmpty();
});

it('fails when debugbar is in require', function () {
    file_put_contents($this->tmpDir.'/composer.json', json_encode([
        'name' => 'example/app',
        'require' => [
            'php' => '^8.2',
            'barryvdh/laravel-debugbar' => '^3.0',
        ],
    ]));

    $check = new DebugToolbarsCheck($this->tmpDir);
    $findings = iterator_to_array($check->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('repo.debug-toolbars')
        ->and($findings[0]->message)->toContain('barryvdh/laravel-debugbar');
});

it('fails when telescope is in require', function () {
    file_put_contents($this->tmpDir.'/composer.json', json_encode([
        'name' => 'example/app',
        'require' => [
            'php' => '^8.2',
            'laravel/telescope' => '^5.0',
        ],
    ]));

    $check = new DebugToolbarsCheck($this->tmpDir);
    $findings = iterator_to_array($check->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('repo.debug-toolbars')
        ->and($findings[0]->message)->toContain('laravel/telescope');
});

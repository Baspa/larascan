<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Logging\CustomErrorPagesCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

function customErrorPagesRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-custom-error-pages-'.uniqid();
    mkdir($this->tmpDir, recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    customErrorPagesRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new CustomErrorPagesCheck($this->tmpDir);

    expect($check->id())->toBe('logging.custom-error-pages')
        ->and($check->category())->toBe(Category::Logging)
        ->and($check->severity())->toBe(Severity::Low);
});

it('is not applicable when resources/views directory is missing', function () {
    $check = new CustomErrorPagesCheck($this->tmpDir);

    expect($check->isApplicable())->toBeFalse();
});

it('passes when both 500.blade.php and 503.blade.php exist', function () {
    mkdir($this->tmpDir.'/resources/views/errors', recursive: true);
    file_put_contents($this->tmpDir.'/resources/views/errors/500.blade.php', 'oops');
    file_put_contents($this->tmpDir.'/resources/views/errors/503.blade.php', 'maintenance');

    $check = new CustomErrorPagesCheck($this->tmpDir);
    $findings = iterator_to_array($check->run());

    expect($findings)->toBeEmpty();
});

it('fails when one of the error pages is missing', function () {
    mkdir($this->tmpDir.'/resources/views/errors', recursive: true);
    file_put_contents($this->tmpDir.'/resources/views/errors/500.blade.php', 'oops');

    $check = new CustomErrorPagesCheck($this->tmpDir);
    $findings = iterator_to_array($check->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Low)
        ->and($findings[0]->checkId)->toBe('logging.custom-error-pages')
        ->and($findings[0]->message)->toContain('503.blade.php');
});

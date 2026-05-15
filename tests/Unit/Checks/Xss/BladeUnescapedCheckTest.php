<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Xss\BladeUnescapedCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

function bladeUnescapedRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-blade-unescaped-'.uniqid();
    mkdir($this->tmpDir.'/views', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    bladeUnescapedRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new BladeUnescapedCheck($this->tmpDir.'/views');

    expect($check->id())->toBe('xss.blade-unescaped')
        ->and($check->category())->toBe(Category::Xss)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when no {!! ... !!} patterns are present', function () {
    file_put_contents(
        $this->tmpDir.'/views/home.blade.php',
        "<h1>Welcome</h1>\n<p>{{ \$user->name }}</p>\n",
    );

    $findings = iterator_to_array((new BladeUnescapedCheck($this->tmpDir.'/views'))->run());
    expect($findings)->toBeEmpty();
});

it('passes when {!! ... !!} contains only an HTML string literal', function () {
    file_put_contents(
        $this->tmpDir.'/views/home.blade.php',
        "<h1>Welcome</h1>\n{!! '<strong>safe</strong>' !!}\n",
    );

    $findings = iterator_to_array((new BladeUnescapedCheck($this->tmpDir.'/views'))->run());
    expect($findings)->toBeEmpty();
});

it('fails when {!! \$user->name !!} contains a PHP variable', function () {
    file_put_contents(
        $this->tmpDir.'/views/home.blade.php',
        "<h1>Welcome</h1>\n<p>{!! \$user->name !!}</p>\n",
    );

    $findings = iterator_to_array((new BladeUnescapedCheck($this->tmpDir.'/views'))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('xss.blade-unescaped')
        ->and($findings[0]->message)->toContain('unescaped output');
});

it('reports the correct line number', function () {
    file_put_contents(
        $this->tmpDir.'/views/home.blade.php',
        "<h1>Welcome</h1>\n<p>hello</p>\n<p>world</p>\n{!! \$payload !!}\n",
    );

    $findings = iterator_to_array((new BladeUnescapedCheck($this->tmpDir.'/views'))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->line)->toBe(4);
});

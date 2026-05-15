<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Xss\UrlJavascriptProtocolCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

function urlJavascriptProtocolRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-url-js-protocol-'.uniqid();
    mkdir($this->tmpDir.'/views', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    urlJavascriptProtocolRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new UrlJavascriptProtocolCheck($this->tmpDir.'/views');

    expect($check->id())->toBe('xss.url-javascript-protocol')
        ->and($check->category())->toBe(Category::Xss)
        ->and($check->severity())->toBe(Severity::Medium);
});

it('passes when no javascript: URLs are present', function () {
    file_put_contents(
        $this->tmpDir.'/views/home.blade.php',
        "<a href=\"/safe\">safe</a>\n<img src=\"/image.png\">\n",
    );

    $findings = iterator_to_array((new UrlJavascriptProtocolCheck($this->tmpDir.'/views'))->run());
    expect($findings)->toBeEmpty();
});

it('fails when a javascript: URL is present in href', function () {
    file_put_contents(
        $this->tmpDir.'/views/home.blade.php',
        "<a href=\"javascript:doStuff()\">click</a>\n",
    );

    $findings = iterator_to_array((new UrlJavascriptProtocolCheck($this->tmpDir.'/views'))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->checkId)->toBe('xss.url-javascript-protocol')
        ->and($findings[0]->message)->toContain('javascript:');
});

it('reports the correct line number', function () {
    file_put_contents(
        $this->tmpDir.'/views/home.blade.php',
        "<h1>Welcome</h1>\n<p>hello</p>\n<a href=\"javascript:doStuff()\">click</a>\n",
    );

    $findings = iterator_to_array((new UrlJavascriptProtocolCheck($this->tmpDir.'/views'))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->line)->toBe(3);
});

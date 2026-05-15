<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Xss\HtmlStringCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function htmlStringRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-html-string-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    htmlStringRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new HtmlStringCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('xss.html-string')
        ->and($check->category())->toBe(Category::Xss)
        ->and($check->severity())->toBe(Severity::Medium);
});

it('passes when no HtmlString is instantiated', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return 'plain';\n    }\n}\n",
    );

    $findings = iterator_to_array((new HtmlStringCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when new HtmlString(...) is instantiated', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nuse Illuminate\Support\HtmlString;\nclass UserController {\n    public function index() {\n        return new HtmlString('<b>hi</b>');\n    }\n}\n",
    );

    $findings = iterator_to_array((new HtmlStringCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->checkId)->toBe('xss.html-string')
        ->and($findings[0]->message)->toContain('HtmlString instantiation')
        ->and($findings[0]->line)->toBe(5);
});

it('fails when new \\Illuminate\\Support\\HtmlString(...) is instantiated with the FQCN', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return new \\Illuminate\\Support\\HtmlString('<b>hi</b>');\n    }\n}\n",
    );

    $findings = iterator_to_array((new HtmlStringCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->checkId)->toBe('xss.html-string');
});

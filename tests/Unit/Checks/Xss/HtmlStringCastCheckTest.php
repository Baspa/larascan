<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Xss\HtmlStringCastCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function htmlStringCastRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-htmlstring-cast-'.uniqid();
    mkdir($this->tmpDir.'/app/Models', recursive: true);
});

afterEach(function () {
    htmlStringCastRecursiveRemove($this->tmpDir);
});

it('exposes correct metadata', function () {
    $check = new HtmlStringCastCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('xss.htmlstring-cast')
        ->and($check->category())->toBe(Category::Xss)
        ->and($check->severity())->toBe(Severity::Medium);
});

it('passes when no model uses HtmlString casts', function () {
    file_put_contents(
        $this->tmpDir.'/app/Models/Post.php',
        "<?php\nclass Post { protected \$casts = ['published_at' => 'datetime']; }\n",
    );

    $findings = iterator_to_array((new HtmlStringCastCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when $casts property contains HtmlString::class', function () {
    file_put_contents(
        $this->tmpDir.'/app/Models/Post.php',
        "<?php\nuse Illuminate\Support\HtmlString;\nclass Post { protected \$casts = ['body' => HtmlString::class]; }\n",
    );

    $findings = iterator_to_array((new HtmlStringCastCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->checkId)->toBe('xss.htmlstring-cast')
        ->and($findings[0]->message)->toContain('body');
});

it('fails when casts() method returns array with HtmlString::class', function () {
    file_put_contents(
        $this->tmpDir.'/app/Models/Post.php',
        "<?php\nuse Illuminate\Support\HtmlString;\nclass Post { protected function casts(): array { return ['body' => HtmlString::class]; } }\n",
    );

    $findings = iterator_to_array((new HtmlStringCastCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toContain('body');
});

it('fails on fully-qualified HtmlString::class', function () {
    file_put_contents(
        $this->tmpDir.'/app/Models/Post.php',
        "<?php\nclass Post { protected \$casts = ['body' => \\Illuminate\\Support\\HtmlString::class]; }\n",
    );

    $findings = iterator_to_array((new HtmlStringCastCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1);
});

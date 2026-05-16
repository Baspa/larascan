<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Auth\SignedUrlNoParamsCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function signedUrlRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-signed-url-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    signedUrlRecursiveRemove($this->tmpDir);
});

it('exposes correct metadata', function () {
    $check = new SignedUrlNoParamsCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('auth.signed-url-no-params')
        ->and($check->category())->toBe(Category::Auth)
        ->and($check->severity())->toBe(Severity::Medium);
});

it('passes when signedRoute is called with non-empty params', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/X.php',
        "<?php\nuse Illuminate\Support\Facades\URL;\nclass X { public function go() { return URL::signedRoute('foo', ['user' => 1]); } }\n",
    );

    $findings = iterator_to_array((new SignedUrlNoParamsCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when signedRoute is called with no params', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/X.php',
        "<?php\nuse Illuminate\Support\Facades\URL;\nclass X { public function go() { return URL::signedRoute('foo'); } }\n",
    );

    $findings = iterator_to_array((new SignedUrlNoParamsCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->checkId)->toBe('auth.signed-url-no-params')
        ->and($findings[0]->message)->toContain('signedRoute');
});

it('fails when temporarySignedRoute is called with empty params array', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/X.php',
        "<?php\nuse Illuminate\Support\Facades\URL;\nclass X { public function go() { return URL::temporarySignedRoute('foo', now()->addHour(), []); } }\n",
    );

    $findings = iterator_to_array((new SignedUrlNoParamsCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toContain('temporarySignedRoute');
});

it('passes when temporarySignedRoute has non-empty params', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/X.php',
        "<?php\nuse Illuminate\Support\Facades\URL;\nclass X { public function go() { return URL::temporarySignedRoute('foo', now()->addHour(), ['user' => 1]); } }\n",
    );

    $findings = iterator_to_array((new SignedUrlNoParamsCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

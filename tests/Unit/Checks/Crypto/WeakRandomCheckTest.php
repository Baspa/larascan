<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Crypto\WeakRandomCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function weakRandomRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-weak-random-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    weakRandomRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new WeakRandomCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('crypto.weak-random')
        ->and($check->category())->toBe(Category::Crypto)
        ->and($check->severity())->toBe(Severity::High);
});

it('is skipped when app/ is missing', function () {
    weakRandomRecursiveRemove($this->tmpDir.'/app');

    $check = new WeakRandomCheck($this->tmpDir.'/app', new FileParser);
    expect($check->isApplicable())->toBeFalse();
});

it('passes when only random_int / random_bytes are used', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function token() {\n        return bin2hex(random_bytes(16)) . random_int(0, 9);\n    }\n}\n",
    );

    $findings = iterator_to_array((new WeakRandomCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when rand() is called', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function token() {\n        return rand(0, 1000);\n    }\n}\n",
    );

    $findings = iterator_to_array((new WeakRandomCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('crypto.weak-random')
        ->and($findings[0]->message)->toContain("'rand'");
});

it('fails when mt_rand() is called', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function token() {\n        return mt_rand(0, 1000);\n    }\n}\n",
    );

    $findings = iterator_to_array((new WeakRandomCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toContain("'mt_rand'");
});

it('fails when uniqid() is called', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function token() {\n        return uniqid('prefix-');\n    }\n}\n",
    );

    $findings = iterator_to_array((new WeakRandomCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toContain("'uniqid'");
});

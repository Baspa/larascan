<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Crypto\WeakHashCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function weakHashRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-weak-hash-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    weakHashRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new WeakHashCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('crypto.weak-hash')
        ->and($check->category())->toBe(Category::Crypto)
        ->and($check->severity())->toBe(Severity::High);
});

it('is skipped when app/ is missing', function () {
    weakHashRecursiveRemove($this->tmpDir.'/app');

    $check = new WeakHashCheck($this->tmpDir.'/app', new FileParser);
    expect($check->isApplicable())->toBeFalse();
});

it('passes when only strong hashes are used', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return hash('sha256', 'data');\n    }\n}\n",
    );

    $findings = iterator_to_array((new WeakHashCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when md5() is called', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return md5('data');\n    }\n}\n",
    );

    $findings = iterator_to_array((new WeakHashCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('crypto.weak-hash')
        ->and($findings[0]->message)->toContain("'md5'")
        ->and($findings[0]->line)->toBe(4);
});

it('fails when sha1() is called', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return sha1('data');\n    }\n}\n",
    );

    $findings = iterator_to_array((new WeakHashCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toContain("'sha1'");
});

it("fails when hash('md5', ...) is called", function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return hash('md5', 'data');\n    }\n}\n",
    );

    $findings = iterator_to_array((new WeakHashCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toContain("hash('md5'");
});

it("does not fire on hash('sha256', ...)", function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return hash('sha256', 'data');\n    }\n}\n",
    );

    $findings = iterator_to_array((new WeakHashCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Injection\UnserializeCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function unserializeRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-unserialize-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    unserializeRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new UnserializeCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('injection.unserialize')
        ->and($check->category())->toBe(Category::Injection)
        ->and($check->severity())->toBe(Severity::Critical);
});

it('is skipped when app/ is missing', function () {
    unserializeRecursiveRemove($this->tmpDir.'/app');

    $check = new UnserializeCheck($this->tmpDir.'/app', new FileParser);
    expect($check->isApplicable())->toBeFalse();
});

it('passes when no unserialize() is used', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return json_decode('{}', true);\n    }\n}\n",
    );

    $findings = iterator_to_array((new UnserializeCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when unserialize() is called', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index(\$payload) {\n        return unserialize(\$payload);\n    }\n}\n",
    );

    $findings = iterator_to_array((new UnserializeCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('injection.unserialize')
        ->and($findings[0]->message)->toContain('unserialize()')
        ->and($findings[0]->line)->toBe(4);
});

it('reports each unserialize() call separately', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function a(\$x) { return unserialize(\$x); }\n    public function b(\$y) { return unserialize(\$y); }\n}\n",
    );

    $findings = iterator_to_array((new UnserializeCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toHaveCount(2);
});

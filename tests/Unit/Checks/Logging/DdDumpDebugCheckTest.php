<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Logging\DdDumpDebugCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function ddDumpRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-dd-dump-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    ddDumpRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new DdDumpDebugCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('logging.dd-dump-debug')
        ->and($check->category())->toBe(Category::Logging)
        ->and($check->severity())->toBe(Severity::Medium);
});

it('passes when there are no dd/dump/var_dump calls', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nnamespace App\\Http\\Controllers;\nclass UserController {\n    public function index() {\n        return 'ok';\n    }\n}\n",
    );

    $findings = iterator_to_array((new DdDumpDebugCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when dd() is called', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nnamespace App\\Http\\Controllers;\nclass UserController {\n    public function index() {\n        dd('hello');\n    }\n}\n",
    );

    $findings = iterator_to_array((new DdDumpDebugCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->checkId)->toBe('logging.dd-dump-debug')
        ->and($findings[0]->message)->toContain('dd()');
});

it('fails when dump() is called', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nnamespace App\\Http\\Controllers;\nclass UserController {\n    public function index() {\n        dump('hello');\n    }\n}\n",
    );

    $findings = iterator_to_array((new DdDumpDebugCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toContain('dump()');
});

it('fails when var_dump() is called', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nnamespace App\\Http\\Controllers;\nclass UserController {\n    public function index() {\n        var_dump('hello');\n    }\n}\n",
    );

    $findings = iterator_to_array((new DdDumpDebugCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toContain('var_dump()');
});

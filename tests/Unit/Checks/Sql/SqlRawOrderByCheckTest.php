<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Sql\SqlRawOrderByCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function sqlRawOrderByRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-sql-raw-order-by-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    sqlRawOrderByRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new SqlRawOrderByCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('sql.raw-order-by')
        ->and($check->category())->toBe(Category::Sql)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when no orderByRaw calls are present', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return User::query()->orderBy('id')->get();\n    }\n}\n",
    );

    $findings = iterator_to_array((new SqlRawOrderByCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('passes when orderByRaw uses a literal string', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return User::query()->orderByRaw('id ASC')->get();\n    }\n}\n",
    );

    $findings = iterator_to_array((new SqlRawOrderByCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when ->orderByRaw() uses $request->input()', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index(\$request) {\n        return User::query()->orderByRaw(\$request->input('sort'))->get();\n    }\n}\n",
    );

    $findings = iterator_to_array((new SqlRawOrderByCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('sql.raw-order-by')
        ->and($findings[0]->message)->toContain('orderByRaw with user input')
        ->and($findings[0]->message)->toContain('SQL injection in ORDER BY clause');
});

it('fails when ->orderByRaw() uses request() helper', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return User::query()->orderByRaw(request('sort'))->get();\n    }\n}\n",
    );

    $findings = iterator_to_array((new SqlRawOrderByCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('sql.raw-order-by')
        ->and($findings[0]->message)->toContain('orderByRaw with user input')
        ->and($findings[0]->message)->toContain('Validate sort column against an allowlist');
});

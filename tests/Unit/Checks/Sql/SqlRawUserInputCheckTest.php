<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Sql\SqlRawUserInputCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function sqlRawUserInputRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-sql-raw-user-input-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    sqlRawUserInputRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new SqlRawUserInputCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('sql.raw-user-input')
        ->and($check->category())->toBe(Category::Sql)
        ->and($check->severity())->toBe(Severity::Critical);
});

it('passes when no raw SQL calls are present', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return User::all();\n    }\n}\n",
    );

    $findings = iterator_to_array((new SqlRawUserInputCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('passes when DB::raw uses a literal string', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nuse Illuminate\\Support\\Facades\\DB;\nclass UserController {\n    public function index() {\n        return DB::raw('count(*)');\n    }\n}\n",
    );

    $findings = iterator_to_array((new SqlRawUserInputCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when DB::raw uses $request->input()', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nuse Illuminate\\Support\\Facades\\DB;\nclass UserController {\n    public function index(\$request) {\n        return DB::raw(\$request->input('expr'));\n    }\n}\n",
    );

    $findings = iterator_to_array((new SqlRawUserInputCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('sql.raw-user-input')
        ->and($findings[0]->message)->toContain('SQL injection risk')
        ->and($findings[0]->message)->toContain('DB::raw');
});

it('fails when ->whereRaw() uses $request->input()', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index(\$request) {\n        return User::query()->whereRaw(\$request->input('cond'))->get();\n    }\n}\n",
    );

    $findings = iterator_to_array((new SqlRawUserInputCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('sql.raw-user-input')
        ->and($findings[0]->message)->toContain('whereRaw');
});

it('fails when ->selectRaw() uses request() helper', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return User::query()->selectRaw(request('cols'))->get();\n    }\n}\n",
    );

    $findings = iterator_to_array((new SqlRawUserInputCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('sql.raw-user-input')
        ->and($findings[0]->message)->toContain('selectRaw');
});

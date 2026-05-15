<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Sql\SqlVariableTableColumnCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function sqlVariableTableColumnRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-sql-variable-table-column-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    sqlVariableTableColumnRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new SqlVariableTableColumnCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('sql.variable-table-column')
        ->and($check->category())->toBe(Category::Sql)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when DB::table() uses a literal string', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nuse Illuminate\\Support\\Facades\\DB;\nclass UserController {\n    public function index() {\n        return DB::table('users')->get();\n    }\n}\n",
    );

    $findings = iterator_to_array((new SqlVariableTableColumnCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when DB::table() uses a variable', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nuse Illuminate\\Support\\Facades\\DB;\nclass UserController {\n    public function index(\$tableName) {\n        return DB::table(\$tableName)->get();\n    }\n}\n",
    );

    $findings = iterator_to_array((new SqlVariableTableColumnCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('sql.variable-table-column')
        ->and($findings[0]->message)->toContain('Variable DB::table() argument')
        ->and($findings[0]->message)->toContain('Validate against an allowlist');
});

it('fails when ->from() uses a variable', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nuse Illuminate\\Support\\Facades\\DB;\nclass UserController {\n    public function index(\$t) {\n        return DB::query()->from(\$t)->get();\n    }\n}\n",
    );

    $findings = iterator_to_array((new SqlVariableTableColumnCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('sql.variable-table-column')
        ->and($findings[0]->message)->toContain('Variable ->from() argument');
});

it('passes when ->select() uses only string literals', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nuse Illuminate\\Support\\Facades\\DB;\nclass UserController {\n    public function index() {\n        DB::table('users')->select('*')->get();\n        DB::table('users')->select('col1', 'col2')->get();\n    }\n}\n",
    );

    $findings = iterator_to_array((new SqlVariableTableColumnCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

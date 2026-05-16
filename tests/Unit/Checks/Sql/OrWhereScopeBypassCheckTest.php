<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Sql\OrWhereScopeBypassCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function orWhereScopeRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-orwhere-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    orWhereScopeRecursiveRemove($this->tmpDir);
});

it('exposes correct metadata', function () {
    $check = new OrWhereScopeBypassCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('sql.orwhere-scope-bypass')
        ->and($check->category())->toBe(Category::Sql)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when orWhere is inside a closure group', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/X.php',
        "<?php\nclass X { public function go() { return User::where('active', 1)->where(function (\$q) { \$q->where('email', 'a')->orWhere('email', 'b'); })->get(); } }\n",
    );

    $findings = iterator_to_array((new OrWhereScopeBypassCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when orWhere is chained directly after where', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/X.php',
        "<?php\nclass X { public function go() { return User::where('active', 1)->orWhere('admin', true)->get(); } }\n",
    );

    $findings = iterator_to_array((new OrWhereScopeBypassCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('sql.orwhere-scope-bypass')
        ->and($findings[0]->message)->toContain('orWhere');
});

it('passes when orWhere appears alone (no where before it)', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/X.php',
        "<?php\nclass X { public function go() { return User::query()->orWhere('admin', true)->get(); } }\n",
    );

    $findings = iterator_to_array((new OrWhereScopeBypassCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('passes when orWhere is inside an arrow function group', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/X.php',
        "<?php\nclass X { public function go() { return User::where('active', 1)->where(fn (\$q) => \$q->where('a', 1)->orWhere('b', 2))->get(); } }\n",
    );

    $findings = iterator_to_array((new OrWhereScopeBypassCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('reports only once for a chain with multiple orWhere calls', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/X.php',
        "<?php\nclass X { public function go() { return User::where('active', 1)->orWhere('a', 1)->orWhere('b', 2)->get(); } }\n",
    );

    $findings = iterator_to_array((new OrWhereScopeBypassCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toHaveCount(1);
});

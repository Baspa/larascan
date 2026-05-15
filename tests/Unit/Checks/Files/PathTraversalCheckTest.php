<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Files\PathTraversalCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function pathTraversalRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-path-traversal-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    pathTraversalRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new PathTraversalCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('files.path-traversal')
        ->and($check->category())->toBe(Category::Files)
        ->and($check->severity())->toBe(Severity::Critical);
});

it('passes when no Storage/File calls are present', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return view('home');\n    }\n}\n",
    );

    $findings = iterator_to_array((new PathTraversalCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('passes when Storage::get() uses a literal string', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return Storage::get('/fixed/path.txt');\n    }\n}\n",
    );

    $findings = iterator_to_array((new PathTraversalCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when Storage::put() uses $request->input()', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function store(\$request) {\n        return Storage::put(\$request->input('path'), 'contents');\n    }\n}\n",
    );

    $findings = iterator_to_array((new PathTraversalCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('files.path-traversal')
        ->and($findings[0]->message)->toContain('path traversal possible')
        ->and($findings[0]->line)->toBe(4);
});

it('fails when File::delete() uses request() helper', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function destroy() {\n        return File::delete(request('path'));\n    }\n}\n",
    );

    $findings = iterator_to_array((new PathTraversalCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('files.path-traversal')
        ->and($findings[0]->message)->toContain('path traversal possible');
});

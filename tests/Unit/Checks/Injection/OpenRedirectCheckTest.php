<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Injection\OpenRedirectCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function openRedirectRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-open-redirect-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    openRedirectRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new OpenRedirectCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('injection.open-redirect')
        ->and($check->category())->toBe(Category::Injection)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when no redirect calls are present', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return view('home');\n    }\n}\n",
    );

    $findings = iterator_to_array((new OpenRedirectCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('passes when redirect() target is a literal string', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return redirect('/fixed-url');\n    }\n}\n",
    );

    $findings = iterator_to_array((new OpenRedirectCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when redirect() uses $request->input()', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index(\$request) {\n        return redirect(\$request->input('url'));\n    }\n}\n",
    );

    $findings = iterator_to_array((new OpenRedirectCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('injection.open-redirect')
        ->and($findings[0]->message)->toContain('open redirect risk')
        ->and($findings[0]->line)->toBe(4);
});

it('fails when redirect() uses request() helper', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return redirect(request('back'));\n    }\n}\n",
    );

    $findings = iterator_to_array((new OpenRedirectCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('injection.open-redirect');
});

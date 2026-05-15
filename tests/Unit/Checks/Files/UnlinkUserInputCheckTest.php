<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Files\UnlinkUserInputCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function unlinkUserInputRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-unlink-user-input-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    unlinkUserInputRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new UnlinkUserInputCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('files.unlink-user-input')
        ->and($check->category())->toBe(Category::Files)
        ->and($check->severity())->toBe(Severity::Critical);
});

it('passes when no unlink/rmdir calls are present', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return view('home');\n    }\n}\n",
    );

    $findings = iterator_to_array((new UnlinkUserInputCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when unlink() is called', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function destroy(\$path) {\n        unlink(\$path);\n    }\n}\n",
    );

    $findings = iterator_to_array((new UnlinkUserInputCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('files.unlink-user-input')
        ->and($findings[0]->message)->toContain('unlink()')
        ->and($findings[0]->line)->toBe(4);
});

it('fails when rmdir() is called', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function destroy(\$dir) {\n        rmdir(\$dir);\n    }\n}\n",
    );

    $findings = iterator_to_array((new UnlinkUserInputCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('files.unlink-user-input')
        ->and($findings[0]->message)->toContain('rmdir()')
        ->and($findings[0]->line)->toBe(4);
});

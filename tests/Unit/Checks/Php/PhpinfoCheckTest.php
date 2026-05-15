<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Php\PhpinfoCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function phpinfoRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-phpinfo-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    phpinfoRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new PhpinfoCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('php.phpinfo')
        ->and($check->category())->toBe(Category::Php)
        ->and($check->severity())->toBe(Severity::Critical);
});

it('is skipped when app/ is missing', function () {
    phpinfoRecursiveRemove($this->tmpDir.'/app');

    $check = new PhpinfoCheck($this->tmpDir.'/app', new FileParser);
    expect($check->isApplicable())->toBeFalse();
});

it('passes when no phpinfo() calls are present in app/', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() { return phpversion(); }\n}\n",
    );

    $findings = iterator_to_array((new PhpinfoCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when phpinfo() is called and reports correct file + line', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/DebugController.php',
        "<?php\nclass DebugController {\n    public function info() {\n        phpinfo();\n    }\n}\n",
    );

    $findings = iterator_to_array((new PhpinfoCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('php.phpinfo')
        ->and($findings[0]->file)->toContain('DebugController.php')
        ->and($findings[0]->line)->toBe(4);
});

it('reports multiple phpinfo() calls as separate findings', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/DebugController.php',
        "<?php\nphpinfo();\nphpinfo();\n",
    );

    $findings = iterator_to_array((new PhpinfoCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toHaveCount(2);
});

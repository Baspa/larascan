<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Config\EnvCallsOutsideConfigCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function envCallsRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-envcalls-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    envCallsRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new EnvCallsOutsideConfigCheck($this->tmpDir, new FileParser);

    expect($check->id())->toBe('config.env-calls-outside-config')
        ->and($check->category())->toBe(Category::Config)
        ->and($check->severity())->toBe(Severity::Medium);
});

it('is skipped when app/ is missing', function () {
    envCallsRecursiveRemove($this->tmpDir.'/app');

    $check = new EnvCallsOutsideConfigCheck($this->tmpDir, new FileParser);
    expect($check->isApplicable())->toBeFalse();
});

it('passes when no env() calls are found in app/', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() { return config('app.name'); }\n}\n",
    );

    $findings = iterator_to_array((new EnvCallsOutsideConfigCheck($this->tmpDir, new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when env() is called inside app/', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function key() { return env('APP_KEY'); }\n}\n",
    );

    $findings = iterator_to_array((new EnvCallsOutsideConfigCheck($this->tmpDir, new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->file)->toContain('UserController.php')
        ->and($findings[0]->line)->toBe(3);
});

it('reports multiple env() calls as separate findings', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\n\$a = env('A');\n\$b = env('B');\n\$c = env('C');\n",
    );

    $findings = iterator_to_array((new EnvCallsOutsideConfigCheck($this->tmpDir, new FileParser))->run());
    expect($findings)->toHaveCount(3);
});

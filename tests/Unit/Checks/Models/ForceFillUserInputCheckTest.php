<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Models\ForceFillUserInputCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function forceFillRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-force-fill-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    forceFillRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new ForceFillUserInputCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('models.force-fill-user-input')
        ->and($check->category())->toBe(Category::Models)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when there are no forceFill calls', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nnamespace App\\Http\\Controllers;\nclass UserController {\n    public function update() {\n        \$user = new \\stdClass();\n        \$user->fill(['name' => 'Bob']);\n    }\n}\n",
    );

    $findings = iterator_to_array((new ForceFillUserInputCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when forceFill is called', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nnamespace App\\Http\\Controllers;\nclass UserController {\n    public function update(\$user, \$request) {\n        \$user->forceFill(\$request->all());\n    }\n}\n",
    );

    $findings = iterator_to_array((new ForceFillUserInputCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('models.force-fill-user-input');
});

it('reports correct file and line', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nnamespace App\\Http\\Controllers;\nclass UserController {\n    public function update(\$user, \$request) {\n        \$user->forceFill(\$request->all());\n    }\n}\n",
    );

    $findings = iterator_to_array((new ForceFillUserInputCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->file)->toContain('UserController.php')
        ->and($findings[0]->line)->toBe(5);
});

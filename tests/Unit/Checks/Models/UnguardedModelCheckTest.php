<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Models\UnguardedModelCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function unguardedRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-unguarded-'.uniqid();
    mkdir($this->tmpDir.'/app/Models', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    unguardedRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new UnguardedModelCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('models.unguarded')
        ->and($check->category())->toBe(Category::Models)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when no model has $guarded = []', function () {
    file_put_contents(
        $this->tmpDir.'/app/Models/User.php',
        "<?php\nnamespace App\\Models;\nclass User {\n    protected \$guarded = ['id'];\n}\n",
    );

    $findings = iterator_to_array((new UnguardedModelCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when a model has $guarded = [] and reports correct file + line', function () {
    file_put_contents(
        $this->tmpDir.'/app/Models/User.php',
        "<?php\nnamespace App\\Models;\nclass User {\n    protected \$guarded = [];\n}\n",
    );

    $findings = iterator_to_array((new UnguardedModelCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('models.unguarded')
        ->and($findings[0]->file)->toContain('User.php')
        ->and($findings[0]->line)->toBe(4);
});

it('does not false-positive on $guarded = [\'*\']', function () {
    file_put_contents(
        $this->tmpDir.'/app/Models/User.php',
        "<?php\nnamespace App\\Models;\nclass User {\n    protected \$guarded = ['*'];\n}\n",
    );

    $findings = iterator_to_array((new UnguardedModelCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('does not false-positive on $fillable = []', function () {
    file_put_contents(
        $this->tmpDir.'/app/Models/User.php',
        "<?php\nnamespace App\\Models;\nclass User {\n    protected \$fillable = [];\n}\n",
    );

    $findings = iterator_to_array((new UnguardedModelCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

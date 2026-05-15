<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Models\ForeignKeyFillableCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function foreignKeyFillableRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-fk-fillable-'.uniqid();
    mkdir($this->tmpDir.'/app/Models', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    foreignKeyFillableRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new ForeignKeyFillableCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('models.foreign-key-fillable')
        ->and($check->category())->toBe(Category::Models)
        ->and($check->severity())->toBe(Severity::Medium);
});

it('passes when no fillable arrays exist', function () {
    file_put_contents(
        $this->tmpDir.'/app/Models/Post.php',
        "<?php\nnamespace App\\Models;\nclass Post {\n    protected \$guarded = ['id'];\n}\n",
    );

    $findings = iterator_to_array((new ForeignKeyFillableCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('passes when fillable has only non-FK columns', function () {
    file_put_contents(
        $this->tmpDir.'/app/Models/Post.php',
        "<?php\nnamespace App\\Models;\nclass Post {\n    protected \$fillable = ['title', 'body', 'published_at'];\n}\n",
    );

    $findings = iterator_to_array((new ForeignKeyFillableCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when fillable contains user_id', function () {
    file_put_contents(
        $this->tmpDir.'/app/Models/Post.php',
        "<?php\nnamespace App\\Models;\nclass Post {\n    protected \$fillable = ['title', 'user_id'];\n}\n",
    );

    $findings = iterator_to_array((new ForeignKeyFillableCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->checkId)->toBe('models.foreign-key-fillable')
        ->and($findings[0]->file)->toContain('Post.php')
        ->and($findings[0]->message)->toContain("'user_id'");
});

it('fails when fillable contains multiple FK columns', function () {
    file_put_contents(
        $this->tmpDir.'/app/Models/Post.php',
        "<?php\nnamespace App\\Models;\nclass Post {\n    protected \$fillable = ['title', 'user_id', 'tenant_id', 'category_id'];\n}\n",
    );

    $findings = iterator_to_array((new ForeignKeyFillableCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(3);

    $columns = array_map(fn ($f) => $f->message, $findings);
    expect($columns[0])->toContain("'user_id'")
        ->and($columns[1])->toContain("'tenant_id'")
        ->and($columns[2])->toContain("'category_id'");
});

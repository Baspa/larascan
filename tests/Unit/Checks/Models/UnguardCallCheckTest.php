<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Models\UnguardCallCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function unguardCallRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-unguard-call-'.uniqid();
    mkdir($this->tmpDir.'/app/Providers', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    unguardCallRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new UnguardCallCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('models.unguard-call')
        ->and($check->category())->toBe(Category::Models)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when there are no unguard() calls', function () {
    file_put_contents(
        $this->tmpDir.'/app/Providers/AppServiceProvider.php',
        "<?php\nnamespace App\\Providers;\nclass AppServiceProvider {\n    public function boot() {\n        // nothing\n    }\n}\n",
    );

    $findings = iterator_to_array((new UnguardCallCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when Model::unguard() is called and reports correct file + line', function () {
    file_put_contents(
        $this->tmpDir.'/app/Providers/AppServiceProvider.php',
        "<?php\nnamespace App\\Providers;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass AppServiceProvider {\n    public function boot() {\n        Model::unguard();\n    }\n}\n",
    );

    $findings = iterator_to_array((new UnguardCallCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('models.unguard-call')
        ->and($findings[0]->file)->toContain('AppServiceProvider.php')
        ->and($findings[0]->line)->toBe(6);
});

it('detects unguard() on subclasses too', function () {
    file_put_contents(
        $this->tmpDir.'/app/Providers/AppServiceProvider.php',
        "<?php\nnamespace App\\Providers;\nuse App\\Models\\User;\nclass AppServiceProvider {\n    public function boot() {\n        User::unguard();\n    }\n}\n",
    );

    $findings = iterator_to_array((new UnguardCallCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->line)->toBe(6);
});

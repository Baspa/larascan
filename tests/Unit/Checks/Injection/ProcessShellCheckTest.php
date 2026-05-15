<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Injection\ProcessShellCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function processShellRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-process-shell-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    processShellRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new ProcessShellCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('injection.process-shell')
        ->and($check->category())->toBe(Category::Injection)
        ->and($check->severity())->toBe(Severity::High);
});

it('is skipped when app/ is missing', function () {
    processShellRecursiveRemove($this->tmpDir.'/app');

    $check = new ProcessShellCheck($this->tmpDir.'/app', new FileParser);
    expect($check->isApplicable())->toBeFalse();
});

it('passes when Process is used with the array form', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/RunController.php',
        "<?php\nuse Symfony\\Component\\Process\\Process;\nclass RunController {\n    public function run() {\n        \$p = new Process(['ls', '-la']);\n        \$p->run();\n    }\n}\n",
    );

    $findings = iterator_to_array((new ProcessShellCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when Process::fromShellCommandline() is called via short alias', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/RunController.php',
        "<?php\nuse Symfony\\Component\\Process\\Process;\nclass RunController {\n    public function run() {\n        Process::fromShellCommandline('ls -la');\n    }\n}\n",
    );

    $findings = iterator_to_array((new ProcessShellCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('injection.process-shell')
        ->and($findings[0]->message)->toContain('Process::fromShellCommandline')
        ->and($findings[0]->line)->toBe(5);
});

it('fails when called via fully-qualified Symfony\\Component\\Process\\Process', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/RunController.php',
        "<?php\nclass RunController {\n    public function run() {\n        \\Symfony\\Component\\Process\\Process::fromShellCommandline('ls');\n    }\n}\n",
    );

    $findings = iterator_to_array((new ProcessShellCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->line)->toBe(4);
});

it('ignores fromShellCommandline on an unrelated class', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/RunController.php',
        "<?php\nclass RunController {\n    public function run() {\n        SomeOther::fromShellCommandline('ls');\n    }\n}\n",
    );

    $findings = iterator_to_array((new ProcessShellCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

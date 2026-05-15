<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Injection\CommandInjectionCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function commandInjectionRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-command-injection-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    commandInjectionRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new CommandInjectionCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('injection.command')
        ->and($check->category())->toBe(Category::Injection)
        ->and($check->severity())->toBe(Severity::Critical);
});

it('is skipped when app/ is missing', function () {
    commandInjectionRecursiveRemove($this->tmpDir.'/app');

    $check = new CommandInjectionCheck($this->tmpDir.'/app', new FileParser);
    expect($check->isApplicable())->toBeFalse();
});

it('passes when no command exec functions are used', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return 'safe';\n    }\n}\n",
    );

    $findings = iterator_to_array((new CommandInjectionCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('detects the exec call', function () {
    $fn = 'exec';
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        {$fn}('ls -la');\n    }\n}\n",
    );

    $findings = iterator_to_array((new CommandInjectionCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('injection.command')
        ->and($findings[0]->message)->toContain("'{$fn}()'")
        ->and($findings[0]->line)->toBe(4);
});

it('detects shell_exec, system, passthru, popen, proc_open', function () {
    $funcs = ['shell_exec', 'system', 'passthru', 'popen', 'proc_open'];
    $body = "<?php\nclass UserController {\n";
    foreach ($funcs as $i => $f) {
        $body .= "    public function m{$i}() { {$f}('ls'); }\n";
    }
    $body .= "}\n";

    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        $body,
    );

    $findings = iterator_to_array((new CommandInjectionCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(5);

    $messages = array_map(fn ($f) => $f->message, $findings);
    $joined = implode("\n", $messages);
    foreach ($funcs as $f) {
        expect($joined)->toContain($f);
    }
});

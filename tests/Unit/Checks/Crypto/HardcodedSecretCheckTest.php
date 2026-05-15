<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Crypto\HardcodedSecretCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function hardcodedSecretRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-hardcoded-secret-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    hardcodedSecretRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new HardcodedSecretCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('crypto.hardcoded-secret')
        ->and($check->category())->toBe(Category::Crypto)
        ->and($check->severity())->toBe(Severity::Critical);
});

it('passes when no secrets are present in code', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        return 'Hello World';\n    }\n}\n",
    );

    $findings = iterator_to_array((new HardcodedSecretCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails on AWS access key pattern', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        \$key = 'AKIAIOSFODNN7EXAMPLE';\n    }\n}\n",
    );

    $findings = iterator_to_array((new HardcodedSecretCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('crypto.hardcoded-secret')
        ->and($findings[0]->message)->toContain('aws-access-key')
        ->and($findings[0]->message)->toContain('move to .env')
        ->and($findings[0]->line)->toBe(4);
});

it('fails on Stripe key pattern', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        \$key = 'sk_live_abcdefghijklmnopqrstuvwx';\n    }\n}\n",
    );

    $findings = iterator_to_array((new HardcodedSecretCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toContain('stripe-key');
});

it('fails on GitHub token pattern', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nclass UserController {\n    public function index() {\n        \$key = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789';\n    }\n}\n",
    );

    $findings = iterator_to_array((new HardcodedSecretCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->message)->toContain('github-pat');
});

it('passes on innocuous strings and class FQCNs', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nuse App\\Models\\User;\nclass UserController {\n    public function index() {\n        \$msg = 'Hello World';\n        \$class = 'App\\\\Models\\\\Order';\n        \$short = 'foo';\n        return \$msg;\n    }\n}\n",
    );

    $findings = iterator_to_array((new HardcodedSecretCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

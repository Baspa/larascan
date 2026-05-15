<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Logging\SensitiveInLogContextCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function sensitiveLogRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-sensitive-log-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    sensitiveLogRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new SensitiveInLogContextCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('logging.sensitive-in-log-context')
        ->and($check->category())->toBe(Category::Logging)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when log context does not contain sensitive keys', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\Log;\nclass UserController {\n    public function index() {\n        Log::info('user logged in', ['user_id' => 5]);\n    }\n}\n",
    );

    $findings = iterator_to_array((new SensitiveInLogContextCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it("fails when log context has 'password' key", function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\Log;\nclass UserController {\n    public function store(\$request) {\n        Log::info('user signup', ['password' => \$request->password]);\n    }\n}\n",
    );

    $findings = iterator_to_array((new SensitiveInLogContextCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('logging.sensitive-in-log-context')
        ->and($findings[0]->message)->toContain("'password'");
});

it("fails when log context has 'token' key", function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/UserController.php',
        "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\Log;\nclass UserController {\n    public function store(\$request) {\n        Log::warning('auth failure', ['token' => \$request->token]);\n    }\n}\n",
    );

    $findings = iterator_to_array((new SensitiveInLogContextCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->message)->toContain("'token'");
});

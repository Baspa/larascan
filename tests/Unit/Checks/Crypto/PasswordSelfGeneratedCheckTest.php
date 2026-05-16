<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Crypto\PasswordSelfGeneratedCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function passwordSelfGenRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-pw-selfgen-'.uniqid();
    mkdir($this->tmpDir.'/app/Http/Controllers', recursive: true);
});

afterEach(function () {
    passwordSelfGenRecursiveRemove($this->tmpDir);
});

it('exposes correct metadata', function () {
    $check = new PasswordSelfGeneratedCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('crypto.password-self-generated')
        ->and($check->category())->toBe(Category::Crypto)
        ->and($check->severity())->toBe(Severity::Medium);
});

it('passes when Str::password() is used for a generated password', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/X.php',
        "<?php\nuse Illuminate\Support\Str;\nuse Illuminate\Support\Facades\Hash;\nclass X { public function go() { \$password = Str::password(12); \$user->password = Hash::make(\$password); } }\n",
    );

    $findings = iterator_to_array((new PasswordSelfGeneratedCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when Str::random is used near a password symbol', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/X.php',
        "<?php\nuse Illuminate\Support\Str;\nuse Illuminate\Support\Facades\Hash;\nclass X { public function go() { \$password = Str::random(10); \$user->password = Hash::make(\$password); } }\n",
    );

    $findings = iterator_to_array((new PasswordSelfGeneratedCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->checkId)->toBe('crypto.password-self-generated')
        ->and($findings[0]->message)->toContain('Str::password');
});

it('fails when md5 is used near a password symbol', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/X.php',
        "<?php\nclass X { public function go() { \$password = md5(uniqid()); \$user->update(['password' => bcrypt(\$password)]); } }\n",
    );

    $findings = iterator_to_array((new PasswordSelfGeneratedCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->checkId)->toBe('crypto.password-self-generated');
});

it('passes when Str::random is used outside a password context', function () {
    file_put_contents(
        $this->tmpDir.'/app/Http/Controllers/X.php',
        "<?php\nuse Illuminate\Support\Str;\nclass X { public function go() { \$token = Str::random(40); return \$token; } }\n",
    );

    $findings = iterator_to_array((new PasswordSelfGeneratedCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

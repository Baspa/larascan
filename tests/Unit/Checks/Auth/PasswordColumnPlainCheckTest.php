<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Auth\PasswordColumnPlainCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Severity;

function passwordColumnRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-password-column-'.uniqid();
    mkdir($this->tmpDir.'/app/Models', recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    passwordColumnRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new PasswordColumnPlainCheck($this->tmpDir.'/app', new FileParser);

    expect($check->id())->toBe('auth.password-column-plain')
        ->and($check->category())->toBe(Category::Auth)
        ->and($check->severity())->toBe(Severity::Critical)
        ->and($check->docsUrl())->toBe('https://github.com/baspa/larascan/blob/main/docs/checks/auth/password-column-plain.md');
});

it('is skipped when there is no User model file', function () {
    $findings = iterator_to_array((new PasswordColumnPlainCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('passes when User has password in $hidden', function () {
    file_put_contents(
        $this->tmpDir.'/app/Models/User.php',
        "<?php\nnamespace App\\Models;\nclass User {\n    protected \$hidden = ['password', 'remember_token'];\n}\n",
    );

    $findings = iterator_to_array((new PasswordColumnPlainCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('passes when User has password => hashed cast', function () {
    file_put_contents(
        $this->tmpDir.'/app/Models/User.php',
        "<?php\nnamespace App\\Models;\nclass User {\n    protected \$casts = ['email_verified_at' => 'datetime', 'password' => 'hashed'];\n}\n",
    );

    $findings = iterator_to_array((new PasswordColumnPlainCheck($this->tmpDir.'/app', new FileParser))->run());
    expect($findings)->toBeEmpty();
});

it('fails when User has neither hidden password nor hashed cast', function () {
    file_put_contents(
        $this->tmpDir.'/app/Models/User.php',
        "<?php\nnamespace App\\Models;\nclass User {\n    protected \$hidden = ['remember_token'];\n    protected \$casts = ['email_verified_at' => 'datetime'];\n}\n",
    );

    $findings = iterator_to_array((new PasswordColumnPlainCheck($this->tmpDir.'/app', new FileParser))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('auth.password-column-plain')
        ->and($findings[0]->file)->toContain('User.php')
        ->and($findings[0]->message)->toContain('hashed');
});

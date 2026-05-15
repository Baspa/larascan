<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Crypto\CipherNotPinnedCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

function cipherPinnedRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-cipher-pinned-'.uniqid();
    mkdir($this->tmpDir, recursive: true);
});

afterEach(function () {
    /** @var string $tmpDir */
    $tmpDir = $this->tmpDir;
    cipherPinnedRecursiveRemove($tmpDir);
});

it('exposes correct metadata', function () {
    $check = new CipherNotPinnedCheck($this->tmpDir);

    expect($check->id())->toBe('crypto.cipher-not-pinned')
        ->and($check->category())->toBe(Category::Crypto)
        ->and($check->severity())->toBe(Severity::Low);
});

it('is skipped when config/app.php is missing', function () {
    $check = new CipherNotPinnedCheck($this->tmpDir);
    expect($check->isApplicable())->toBeFalse();
});

it('fails when app.php has no cipher key', function () {
    file_put_contents("{$this->tmpDir}/app.php", "<?php return ['name' => 'Demo'];");

    $check = new CipherNotPinnedCheck($this->tmpDir);
    $findings = iterator_to_array($check->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Low)
        ->and($findings[0]->checkId)->toBe('crypto.cipher-not-pinned')
        ->and($findings[0]->message)->toContain("'cipher'");
});

it('passes when app.php pins a cipher value', function () {
    file_put_contents("{$this->tmpDir}/app.php", "<?php return ['cipher' => 'AES-256-CBC'];");

    $check = new CipherNotPinnedCheck($this->tmpDir);
    $findings = iterator_to_array($check->run());

    expect($findings)->toBeEmpty();
});

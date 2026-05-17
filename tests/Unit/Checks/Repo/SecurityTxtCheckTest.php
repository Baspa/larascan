<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Repo\SecurityTxtCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

function securityTxtRecursiveRemove(string $dir): void
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
    $this->tmpDir = sys_get_temp_dir().'/larascan-security-txt-'.uniqid();
    mkdir($this->tmpDir.'/public/.well-known', recursive: true);
});

afterEach(function () {
    securityTxtRecursiveRemove($this->tmpDir);
});

it('exposes correct metadata', function () {
    $check = new SecurityTxtCheck($this->tmpDir.'/public');

    expect($check->id())->toBe('repo.security-txt')
        ->and($check->category())->toBe(Category::Repo)
        ->and($check->severity())->toBe(Severity::Low);
});

it('is not applicable when public directory is missing', function () {
    $missing = $this->tmpDir.'/nonexistent-public';

    $check = new SecurityTxtCheck($missing);
    expect($check->isApplicable())->toBeFalse();
});

it('is applicable when public directory exists', function () {
    $check = new SecurityTxtCheck($this->tmpDir.'/public');
    expect($check->isApplicable())->toBeTrue();
});

it('passes when public/.well-known/security.txt exists', function () {
    file_put_contents($this->tmpDir.'/public/.well-known/security.txt', "Contact: mailto:security@example.com\n");

    $findings = iterator_to_array((new SecurityTxtCheck($this->tmpDir.'/public'))->run());
    expect($findings)->toBeEmpty();
});

it('fails when public/.well-known/security.txt is missing', function () {
    $findings = iterator_to_array((new SecurityTxtCheck($this->tmpDir.'/public'))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Low)
        ->and($findings[0]->checkId)->toBe('repo.security-txt')
        ->and($findings[0]->message)->toContain('.well-known/security.txt');
});

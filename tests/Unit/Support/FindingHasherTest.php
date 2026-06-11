<?php

declare(strict_types=1);

use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\FindingHasher;
use Baspa\Larascan\Support\Severity;

it('produces the same hash regardless of line number', function () {
    $hasher = new FindingHasher;

    $a = new Finding('sql.raw-user-input', Severity::Critical, 'Raw SQL', file: 'app/Foo.php', line: 12);
    $b = new Finding('sql.raw-user-input', Severity::Critical, 'Raw SQL', file: 'app/Foo.php', line: 99);

    expect($hasher->hash($a))->toBe($hasher->hash($b));
});

it('produces the same hash regardless of severity', function () {
    $hasher = new FindingHasher;

    $a = new Finding('sql.raw-user-input', Severity::Critical, 'Raw SQL', file: 'app/Foo.php');
    $b = new Finding('sql.raw-user-input', Severity::Info, 'Raw SQL', file: 'app/Foo.php');

    expect($hasher->hash($a))->toBe($hasher->hash($b));
});

it('normalizes line numbers embedded in the message', function () {
    $hasher = new FindingHasher;

    $a = new Finding('auth.api-ability-scoping', Severity::Low, 'createToken() in app/Foo.php:123 is unscoped', file: 'app/Foo.php');
    $b = new Finding('auth.api-ability-scoping', Severity::Low, 'createToken() in app/Foo.php:456 is unscoped', file: 'app/Foo.php');

    expect($hasher->hash($a))->toBe($hasher->hash($b));
});

it('normalizes whitespace differences in the message', function () {
    $hasher = new FindingHasher;

    $a = new Finding('config.app-debug', Severity::Critical, "  APP_DEBUG is\ttrue  in   production\n");
    $b = new Finding('config.app-debug', Severity::Critical, 'APP_DEBUG is true in production');

    expect($hasher->hash($a))->toBe($hasher->hash($b));
});

it('produces different hashes for different files', function () {
    $hasher = new FindingHasher;

    $a = new Finding('sql.raw-user-input', Severity::Critical, 'Raw SQL', file: 'app/Foo.php');
    $b = new Finding('sql.raw-user-input', Severity::Critical, 'Raw SQL', file: 'app/Bar.php');

    expect($hasher->hash($a))->not->toBe($hasher->hash($b));
});

it('produces different hashes for a null file versus a set file', function () {
    $hasher = new FindingHasher;

    $a = new Finding('sql.raw-user-input', Severity::Critical, 'Raw SQL');
    $b = new Finding('sql.raw-user-input', Severity::Critical, 'Raw SQL', file: 'app/Foo.php');

    expect($hasher->hash($a))->not->toBe($hasher->hash($b));
});

it('produces the same hash for Windows and POSIX path separators', function () {
    $hasher = new FindingHasher;

    expect($hasher->hashRaw('sql.raw-user-input', 'app\\Models\\User.php', 'Raw SQL'))
        ->toBe($hasher->hashRaw('sql.raw-user-input', 'app/Models/User.php', 'Raw SQL'));
});

it('produces different hashes for different check ids', function () {
    $hasher = new FindingHasher;

    expect($hasher->hashRaw('config.app-debug', null, 'message'))
        ->not->toBe($hasher->hashRaw('config.app-env', null, 'message'));
});

<?php

declare(strict_types=1);

use Baspa\Larascan\Tools\Output\PhpStanIssue;
use Baspa\Larascan\Tools\PhpStanRunner;

it('parses zero issues from an empty files object', function () {
    $runner = new PhpStanRunner(workingDir: getcwd() ?: '');
    expect(iterator_to_array($runner->parseOutput('{"totals":{"errors":0,"file_errors":0},"files":{},"errors":[]}')))->toBeEmpty();
});

it('parses two issues from the fixture across two files', function () {
    $json = (string) file_get_contents(__DIR__.'/../../Fixtures/audits/phpstan-result.json');
    $runner = new PhpStanRunner(workingDir: getcwd() ?: '');

    $issues = iterator_to_array($runner->parseOutput($json));

    expect($issues)->toHaveCount(2);

    /** @var PhpStanIssue $first */
    $first = $issues[0];
    expect($first)->toBeInstanceOf(PhpStanIssue::class)
        ->and($first->file)->toBe('/app/app/Http/Controllers/UserController.php')
        ->and($first->line)->toBe(42)
        ->and($first->identifier)->toBe('larascan.rawQueryUserInput')
        ->and($first->message)->toContain('SQL injection');

    /** @var PhpStanIssue $second */
    $second = $issues[1];
    expect($second->file)->toBe('/app/app/Models/User.php')
        ->and($second->identifier)->toBe('larascan.unguardedModel');
});

it('isAvailable returns true when vendor/bin/phpstan exists in workingDir', function () {
    $dir = sys_get_temp_dir().'/larascan-phpstan-'.uniqid();
    mkdir($dir.'/vendor/bin', recursive: true);
    file_put_contents($dir.'/vendor/bin/phpstan', '#!/bin/sh');
    chmod($dir.'/vendor/bin/phpstan', 0755);
    try {
        $runner = new PhpStanRunner(workingDir: $dir);
        expect($runner->isAvailable())->toBeTrue();
    } finally {
        unlink($dir.'/vendor/bin/phpstan');
        rmdir($dir.'/vendor/bin');
        rmdir($dir.'/vendor');
        rmdir($dir);
    }
});

it('isAvailable returns false when vendor/bin/phpstan is absent', function () {
    $dir = sys_get_temp_dir().'/larascan-phpstan-'.uniqid();
    mkdir($dir);
    try {
        $runner = new PhpStanRunner(workingDir: $dir);
        expect($runner->isAvailable())->toBeFalse();
    } finally {
        rmdir($dir);
    }
});

it('throws on non-JSON output', function () {
    $runner = new PhpStanRunner(workingDir: getcwd() ?: '');
    expect(fn () => iterator_to_array($runner->parseOutput('garbage')))
        ->toThrow(RuntimeException::class, 'Unable to parse phpstan output');
});

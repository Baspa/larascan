<?php

declare(strict_types=1);

use Baspa\Larascan\Tools\Output\SemgrepMatch;
use Baspa\Larascan\Tools\SemgrepRunner;
use Symfony\Component\Process\ExecutableFinder;

it('parses zero matches from an empty results array', function () {
    $runner = new SemgrepRunner(workingDir: getcwd() ?: '');
    $matches = iterator_to_array($runner->parseOutput('{"version":"1.0","results":[],"errors":[]}'));

    expect($matches)->toBeEmpty();
});

it('parses two matches from the fixture', function () {
    $json = (string) file_get_contents(__DIR__.'/../../Fixtures/audits/semgrep-results.json');
    $runner = new SemgrepRunner(workingDir: getcwd() ?: '');

    $matches = iterator_to_array($runner->parseOutput($json));

    expect($matches)->toHaveCount(2);

    /** @var SemgrepMatch $first */
    $first = $matches[0];
    expect($first)->toBeInstanceOf(SemgrepMatch::class)
        ->and($first->checkId)->toBe('larascan.blade-unescaped-request')
        ->and($first->path)->toBe('resources/views/profile.blade.php')
        ->and($first->line)->toBe(14)
        ->and($first->severity)->toBe('ERROR')
        ->and($first->message)->toContain('XSS');

    /** @var SemgrepMatch $second */
    $second = $matches[1];
    expect($second->checkId)->toBe('larascan.dd-in-production')
        ->and($second->path)->toBe('app/Http/Controllers/UserController.php')
        ->and($second->line)->toBe(42)
        ->and($second->severity)->toBe('WARNING');
});

it('isAvailable depends on the semgrep binary being on PATH', function () {
    $runner = new SemgrepRunner(workingDir: getcwd() ?: '');
    $finder = new ExecutableFinder;
    expect($runner->isAvailable())->toBe($finder->find('semgrep') !== null);
});

it('throws on non-JSON output', function () {
    $runner = new SemgrepRunner(workingDir: getcwd() ?: '');
    expect(fn () => iterator_to_array($runner->parseOutput('not json')))
        ->toThrow(RuntimeException::class, 'Unable to parse semgrep output');
});

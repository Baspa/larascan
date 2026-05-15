<?php

declare(strict_types=1);

use Baspa\Larascan\Tools\ComposerAuditRunner;
use Baspa\Larascan\Tools\Output\ComposerAdvisory;

it('reports composer is available', function () {
    $runner = new ComposerAuditRunner(workingDir: getcwd() ?: '');
    expect($runner->isAvailable())->toBeTrue();
});

it('reports unavailable when the binary cannot be found on PATH', function () {
    $runner = new ComposerAuditRunner(workingDir: getcwd() ?: '', binary: 'definitely-not-a-real-binary-xyz');
    expect($runner->isAvailable())->toBeFalse();
});

it('parses an empty advisories array as zero advisories', function () {
    $json = (string) file_get_contents(__DIR__ . '/../../Fixtures/audits/composer-audit-clean.json');
    $runner = new ComposerAuditRunner(workingDir: getcwd() ?: '');

    $advisories = iterator_to_array($runner->parseOutput($json));
    expect($advisories)->toBeEmpty();
});

it('parses two advisories from the vulnerable fixture', function () {
    $json = (string) file_get_contents(__DIR__ . '/../../Fixtures/audits/composer-audit-vulnerable.json');
    $runner = new ComposerAuditRunner(workingDir: getcwd() ?: '');

    $advisories = iterator_to_array($runner->parseOutput($json));

    expect($advisories)->toHaveCount(2);

    /** @var ComposerAdvisory $first */
    $first = $advisories[0];
    expect($first)->toBeInstanceOf(ComposerAdvisory::class)
        ->and($first->packageName)->toBe('symfony/http-kernel')
        ->and($first->severity)->toBe('medium')
        ->and($first->cve)->toBe('CVE-2022-24894')
        ->and($first->title)->toContain('HttpKernel');

    /** @var ComposerAdvisory $second */
    $second = $advisories[1];
    expect($second->packageName)->toBe('guzzlehttp/guzzle')
        ->and($second->severity)->toBe('high');
});

it('throws on non-JSON output', function () {
    $runner = new ComposerAuditRunner(workingDir: getcwd() ?: '');
    expect(fn () => iterator_to_array($runner->parseOutput('not json {')))
        ->toThrow(RuntimeException::class, 'Unable to parse composer audit output');
});

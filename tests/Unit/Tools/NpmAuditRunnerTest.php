<?php

declare(strict_types=1);

use Baspa\Larascan\Tools\NpmAuditRunner;
use Baspa\Larascan\Tools\Output\NpmAdvisory;
use Symfony\Component\Process\ExecutableFinder;

it('parses an empty vulnerabilities object as zero advisories', function () {
    $json = (string) file_get_contents(__DIR__.'/../../Fixtures/audits/npm-audit-clean.json');
    $runner = new NpmAuditRunner(workingDir: getcwd() ?: '');

    expect(iterator_to_array($runner->parseOutput($json)))->toBeEmpty();
});

it('parses two advisories from the vulnerable fixture', function () {
    $json = (string) file_get_contents(__DIR__.'/../../Fixtures/audits/npm-audit-vulnerable.json');
    $runner = new NpmAuditRunner(workingDir: getcwd() ?: '');

    $advisories = iterator_to_array($runner->parseOutput($json));

    expect($advisories)->toHaveCount(2);

    /** @var NpmAdvisory $lodash */
    $lodash = $advisories[0];
    expect($lodash)->toBeInstanceOf(NpmAdvisory::class)
        ->and($lodash->packageName)->toBe('lodash')
        ->and($lodash->severity)->toBe('high')
        ->and($lodash->title)->toContain('Command Injection')
        ->and($lodash->range)->toBe('<4.17.21');

    /** @var NpmAdvisory $minimist */
    $minimist = $advisories[1];
    expect($minimist->packageName)->toBe('minimist')
        ->and($minimist->severity)->toBe('critical');
});

it('isAvailable returns false when package.json is missing in workingDir', function () {
    $dir = sys_get_temp_dir().'/larascan-npm-'.uniqid();
    mkdir($dir);
    try {
        $runner = new NpmAuditRunner(workingDir: $dir);
        expect($runner->isAvailable())->toBeFalse();
    } finally {
        rmdir($dir);
    }
});

it('isAvailable returns true when package.json exists and npm is on PATH', function () {
    $dir = sys_get_temp_dir().'/larascan-npm-'.uniqid();
    mkdir($dir);
    file_put_contents($dir.'/package.json', '{}');
    try {
        $runner = new NpmAuditRunner(workingDir: $dir);
        if (! (new ExecutableFinder)->find('npm')) {
            $this->markTestSkipped('npm binary not installed');
        }
        expect($runner->isAvailable())->toBeTrue();
    } finally {
        unlink($dir.'/package.json');
        rmdir($dir);
    }
});

it('isAvailable returns false when npm binary cannot be found', function () {
    $dir = sys_get_temp_dir().'/larascan-npm-'.uniqid();
    mkdir($dir);
    file_put_contents($dir.'/package.json', '{}');
    try {
        $runner = new NpmAuditRunner(workingDir: $dir, binary: 'definitely-not-a-real-binary-xyz');
        expect($runner->isAvailable())->toBeFalse();
    } finally {
        unlink($dir.'/package.json');
        rmdir($dir);
    }
});

it('throws on non-JSON output', function () {
    $runner = new NpmAuditRunner(workingDir: getcwd() ?: '');
    expect(fn () => iterator_to_array($runner->parseOutput('garbage')))
        ->toThrow(RuntimeException::class, 'Unable to parse npm audit output');
});

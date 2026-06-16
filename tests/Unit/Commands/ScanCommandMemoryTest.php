<?php

declare(strict_types=1);

use Baspa\Larascan\Commands\ScanCommand;

it('parses memory_limit shorthand into bytes', function (string $value, int $expected) {
    expect(ScanCommand::parseMemoryLimit($value))->toBe($expected);
})->with([
    'unlimited' => ['-1', -1],
    'empty means unlimited' => ['', -1],
    'plain bytes' => ['1048576', 1048576],
    'kilobytes' => ['512K', 512 * 1024],
    'megabytes' => ['128M', 128 * 1024 * 1024],
    'gigabytes' => ['1G', 1024 * 1024 * 1024],
    'lowercase unit' => ['256m', 256 * 1024 * 1024],
    'whitespace tolerant' => [' 64M ', 64 * 1024 * 1024],
]);

it('treats the default 128M as below the 512M scan floor', function () {
    // The command raises memory_limit to 512M only when the configured limit is
    // lower; 128M (a common CLI default) must compare below the floor.
    $floor = 512 * 1024 * 1024;

    expect(ScanCommand::parseMemoryLimit('128M'))->toBeLessThan($floor)
        ->and(ScanCommand::parseMemoryLimit('1G'))->toBeGreaterThan($floor);
});

it('raises to the 512M floor only when the configured limit is lower', function (string $current, ?int $expected) {
    expect(ScanCommand::memoryFloorTarget($current))->toBe($expected);
})->with([
    'default 128M is raised' => ['128M', 512 * 1024 * 1024],
    'exactly at floor stays' => ['512M', null],
    'higher is left alone' => ['1G', null],
    'unlimited is left alone' => ['-1', null],
    'empty is treated as unlimited' => ['', null],
]);

it('produces no diagnostic for a normal or non-fatal last error', function (?array $error) {
    expect(ScanCommand::fatalDiagnostic($error))->toBeNull();
})->with([
    'no error' => [null],
    'warning' => [['type' => E_WARNING, 'message' => 'undefined index', 'file' => 'x', 'line' => 1]],
    'notice' => [['type' => E_NOTICE, 'message' => 'undefined var', 'file' => 'x', 'line' => 1]],
]);

it('reports an OOM with a memory_limit hint', function () {
    $diagnostic = ScanCommand::fatalDiagnostic([
        'type' => E_ERROR,
        'message' => 'Allowed memory size of 134217728 bytes exhausted',
        'file' => 'x',
        'line' => 1,
    ]);

    expect($diagnostic)->not->toBeNull()
        ->and($diagnostic['headline'])->toContain('ran out of memory')
        ->and(implode("\n", $diagnostic['details']))->toContain('memory_limit=-1')
        ->and(implode("\n", $diagnostic['details']))->toContain('Allowed memory size');
});

it('reports a non-OOM fatal without the memory hint', function () {
    $diagnostic = ScanCommand::fatalDiagnostic([
        'type' => E_ERROR,
        'message' => 'Call to undefined function foo()',
        'file' => 'x',
        'line' => 1,
    ]);

    expect($diagnostic)->not->toBeNull()
        ->and($diagnostic['headline'])->toContain('fatal error')
        ->and(implode("\n", $diagnostic['details']))->not->toContain('memory_limit')
        ->and($diagnostic['details'])->toHaveCount(1);
});

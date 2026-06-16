<?php

declare(strict_types=1);

use Baspa\Larascan\Commands\ScanCommand;
use Illuminate\Console\OutputStyle;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

function makeScanCommand(BufferedOutput $buffer): ScanCommand
{
    $command = new ScanCommand;
    $command->setOutput(new OutputStyle(new ArrayInput([]), $buffer));

    return $command;
}

function callPrivate(object $object, string $method, mixed ...$args): mixed
{
    return (new ReflectionClass($object))->getMethod($method)->invoke($object, ...$args);
}

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

it('raises the live memory_limit to the floor when configured lower', function () {
    $original = ini_get('memory_limit');

    try {
        // Below the 512M floor but comfortably above the suite's live usage —
        // PHP refuses to set a limit under current consumption.
        ini_set('memory_limit', '256M');
        callPrivate(makeScanCommand(new BufferedOutput), 'raiseMemoryFloor');

        expect(ScanCommand::parseMemoryLimit((string) ini_get('memory_limit')))
            ->toBe(512 * 1024 * 1024);
    } finally {
        ini_set('memory_limit', (string) $original);
    }
});

it('writes the diagnostic to error output when rendered', function () {
    $buffer = new BufferedOutput;
    $command = makeScanCommand($buffer);

    callPrivate($command, 'renderFatalDiagnostic', [
        'headline' => 'larascan ran out of memory before the scan finished.',
        'details' => ['  Allowed memory size exhausted', '  php -d memory_limit=-1 artisan larascan'],
    ]);

    expect($buffer->fetch())
        ->toContain('ran out of memory')
        ->toContain('memory_limit=-1');
});

it('stays silent on shutdown after a completed scan', function () {
    $buffer = new BufferedOutput;
    $command = makeScanCommand($buffer);

    $completed = (new ReflectionClass($command))->getProperty('scanCompleted');
    $completed->setValue($command, true);

    $command->handleShutdown();

    expect($buffer->fetch())->toBe('');
});

it('stays silent on shutdown when the last error is not a fatal', function () {
    // Most recent error in the test process is non-fatal, so the handler emits
    // nothing even though the scan was not marked completed.
    $buffer = new BufferedOutput;
    $command = makeScanCommand($buffer);

    $command->handleShutdown();

    expect($buffer->fetch())->toBe('');
});

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

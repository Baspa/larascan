<?php

declare(strict_types=1);

it('runs and exits cleanly with no checks registered', function () {
    // At this task no checks are registered yet (AppDebugCheck arrives in Task 13).
    // The table still renders and exit code is 0.
    $this->artisan('larascan:list')->assertExitCode(0);
});

it('accepts a known category filter', function () {
    $this->artisan('larascan:list --category=config')->assertExitCode(0);
});

it('rejects unknown category', function () {
    $this->artisan('larascan:list --category=nope')->assertExitCode(2);
});

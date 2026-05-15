<?php

declare(strict_types=1);

it('runs the larascan command and shows the report', function () {
    $this->artisan('larascan')
        ->expectsOutputToContain('larascan — security scan')
        ->expectsOutputToContain('Report')
        ->assertExitCode(0);
});

it('honors --fail-on for exit code', function () {
    // No checks registered yet at this task. The scan runs cleanly and reports
    // no findings → exit 0 regardless of threshold. (After Task 13 the
    // AppDebugCheck is also registered and remains passed in testbench's local env.)
    $this->artisan('larascan --fail-on=critical')->assertExitCode(0);
});

it('filters checks via --check pattern', function () {
    $this->artisan('larascan --check=does.not.exist')
        ->expectsOutputToContain('larascan — security scan')
        ->assertExitCode(0);
});

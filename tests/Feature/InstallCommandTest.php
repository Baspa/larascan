<?php

declare(strict_types=1);

it('publishes the larascan config file', function () {
    $target = config_path('larascan.php');
    if (file_exists($target)) {
        unlink($target);
    }

    $this->artisan('larascan:install --no-interaction')
        ->expectsOutputToContain('Published')
        ->assertExitCode(0);

    expect(file_exists($target))->toBeTrue();
    unlink($target);
});

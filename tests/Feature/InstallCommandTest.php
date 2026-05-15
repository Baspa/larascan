<?php

declare(strict_types=1);

it('publishes the larascan config file', function () {
    $target = config_path('larascan.php');
    if (file_exists($target)) {
        unlink($target);
    }

    $this->artisan('larascan:install --no-interaction')
        ->expectsOutputToContain('Installation complete!')
        ->assertExitCode(0);

    expect(file_exists($target))->toBeTrue();
    unlink($target);
});

it('publishes the workflow file when --workflow flag is set', function () {
    $workflowPath = base_path('.github/workflows/larascan.yml');
    $configPath = config_path('larascan.php');

    // Clean up beforehand to avoid leakage
    if (file_exists($workflowPath)) {
        unlink($workflowPath);
    }
    if (file_exists($configPath)) {
        unlink($configPath);
    }

    $this->artisan('larascan:install --workflow --no-interaction')
        ->assertExitCode(0);

    expect(file_exists($workflowPath))->toBeTrue();

    // Cleanup after
    if (file_exists($workflowPath)) {
        unlink($workflowPath);
    }
    $workflowsDir = base_path('.github/workflows');
    if (is_dir($workflowsDir) && count(scandir($workflowsDir)) === 2) {
        rmdir($workflowsDir);
    }
    $githubDir = base_path('.github');
    if (is_dir($githubDir) && count(scandir($githubDir)) === 2) {
        rmdir($githubDir);
    }
    if (file_exists($configPath)) {
        unlink($configPath);
    }
});

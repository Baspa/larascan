<?php

declare(strict_types=1);

use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;

it('constructs a finding with the required fields', function () {
    $finding = new Finding(
        checkId: 'cookies.session-secure',
        severity: Severity::Critical,
        message: 'SESSION_SECURE_COOKIE is false',
    );

    expect($finding->checkId)->toBe('cookies.session-secure')
        ->and($finding->severity)->toBe(Severity::Critical)
        ->and($finding->file)->toBeNull()
        ->and($finding->line)->toBeNull();
});

it('accepts file and line for location-aware findings', function () {
    $finding = new Finding(
        checkId: 'sql.raw-user-input',
        severity: Severity::High,
        message: 'DB::raw with user input',
        file: 'app/Http/Controllers/UserController.php',
        line: 42,
    );

    expect($finding->file)->toBe('app/Http/Controllers/UserController.php')
        ->and($finding->line)->toBe(42);
});

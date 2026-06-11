<?php

declare(strict_types=1);

use Baspa\Larascan\Support\Severity;

it('exposes the five severity levels', function () {
    expect(Severity::cases())->toHaveCount(5)
        ->and(Severity::Critical->value)->toBe('critical')
        ->and(Severity::High->value)->toBe('high')
        ->and(Severity::Medium->value)->toBe('medium')
        ->and(Severity::Low->value)->toBe('low')
        ->and(Severity::Info->value)->toBe('info');
});

it('orders severities by rank', function () {
    expect(Severity::Critical->rank())->toBeGreaterThan(Severity::High->rank())
        ->and(Severity::High->rank())->toBeGreaterThan(Severity::Medium->rank())
        ->and(Severity::Medium->rank())->toBeGreaterThan(Severity::Low->rank())
        ->and(Severity::Low->rank())->toBeGreaterThan(Severity::Info->rank());
});

it('compares severities with isAtLeast', function () {
    expect(Severity::Critical->isAtLeast(Severity::High))->toBeTrue()
        ->and(Severity::Low->isAtLeast(Severity::High))->toBeFalse();
});

it('derives severity from CVSS score', function () {
    expect(Severity::fromCvssScore(9.5))->toBe(Severity::Critical)
        ->and(Severity::fromCvssScore(7.5))->toBe(Severity::High)
        ->and(Severity::fromCvssScore(4.5))->toBe(Severity::Medium)
        ->and(Severity::fromCvssScore(2.0))->toBe(Severity::Low)
        ->and(Severity::fromCvssScore(0.0))->toBe(Severity::Info);
});

it('downgrades to Info when env is not production', function () {
    expect(Severity::Critical->downgradeIfNotProduction('local'))->toBe(Severity::Info)
        ->and(Severity::High->downgradeIfNotProduction('testing'))->toBe(Severity::Info)
        ->and(Severity::Medium->downgradeIfNotProduction('staging'))->toBe(Severity::Info);
});

it('keeps the original severity when env is production', function () {
    expect(Severity::Critical->downgradeIfNotProduction('production'))->toBe(Severity::Critical)
        ->and(Severity::High->downgradeIfNotProduction('production'))->toBe(Severity::High);
});

it('maps severity to SARIF level', function (Severity $severity, string $level) {
    expect($severity->sarifLevel())->toBe($level);
})->with([
    [Severity::Critical, 'error'],
    [Severity::High, 'error'],
    [Severity::Medium, 'warning'],
    [Severity::Low, 'note'],
    [Severity::Info, 'note'],
]);

it('maps severity to a security-severity score consistent with fromCvssScore', function (Severity $severity, string $score) {
    expect($severity->securitySeverityScore())->toBe($score)
        ->and(Severity::fromCvssScore((float) $score))->toBe($severity);
})->with([
    [Severity::Critical, '9.8'],
    [Severity::High, '8.0'],
    [Severity::Medium, '5.5'],
    [Severity::Low, '3.0'],
    [Severity::Info, '0.0'],
]);

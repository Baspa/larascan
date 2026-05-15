<?php

declare(strict_types=1);

use Baspa\Larascan\Reporters\SeverityBadge;
use Baspa\Larascan\Support\Severity;

it('returns a colored span for each severity', function () {
    foreach (Severity::cases() as $severity) {
        $html = SeverityBadge::html($severity);
        expect($html)
            ->toStartWith('<span class="')
            ->toEndWith('</span>')
            ->toContain('px-1');
    }
});

it('contains the severity name uppercase', function () {
    expect(SeverityBadge::html(Severity::Critical))->toContain('CRITICAL');
    expect(SeverityBadge::html(Severity::High))->toContain('HIGH');
    expect(SeverityBadge::html(Severity::Medium))->toContain('MEDIUM');
    expect(SeverityBadge::html(Severity::Low))->toContain('LOW');
    expect(SeverityBadge::html(Severity::Info))->toContain('INFO');
});

it('uses different colors for different severities', function () {
    expect(SeverityBadge::html(Severity::Critical))->toContain('bg-red-500');
    expect(SeverityBadge::html(Severity::High))->toContain('bg-red-300');
    expect(SeverityBadge::html(Severity::Medium))->toContain('bg-yellow-400');
    expect(SeverityBadge::html(Severity::Low))->toContain('bg-blue-400');
    expect(SeverityBadge::html(Severity::Info))->toContain('bg-gray-500');
});

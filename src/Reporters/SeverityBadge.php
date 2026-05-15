<?php

declare(strict_types=1);

namespace Baspa\Larascan\Reporters;

use Baspa\Larascan\Support\Severity;

final class SeverityBadge
{
    public static function html(Severity $severity): string
    {
        $label = strtoupper($severity->value);
        $classes = match ($severity) {
            Severity::Critical => 'bg-red-500 text-white',
            Severity::High => 'bg-red-300 text-black',
            Severity::Medium => 'bg-yellow-400 text-black',
            Severity::Low => 'bg-blue-400 text-white',
            Severity::Info => 'bg-gray-500 text-white',
        };

        return sprintf('<span class="%s w-10 text-center">%s</span>', $classes, $label);
    }
}

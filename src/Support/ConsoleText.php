<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

use Symfony\Component\Console\Formatter\OutputFormatter;

final class ConsoleText
{
    /**
     * Make scanned data (file names, messages, errors) safe to embed in console
     * markup: control characters would let it rewrite earlier terminal output,
     * and formatter tags would let it restyle or spoof the report.
     */
    public static function escape(string $text): string
    {
        $text = preg_replace('/[\r\n\t]+/', ' ', $text) ?? $text;
        $text = preg_replace('/[\x00-\x1F\x7F]/', '', $text) ?? $text;
        $text = preg_replace('/[\x{0080}-\x{009F}]/u', '', $text) ?? $text;

        return OutputFormatter::escape($text);
    }
}

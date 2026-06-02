<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

use Laravel\AgentDetector\AgentDetector as LaravelAgentDetector;

/**
 * Detects whether larascan is running under an AI coding agent.
 * Delegates to laravel/agent-detector for the canonical list.
 */
final class AgentDetector
{
    public static function isAgentRun(): bool
    {
        // Manual override always wins.
        $manual = getenv('LARASCAN_AGENT_MODE');
        if ($manual !== false && $manual !== '') {
            return true;
        }

        return LaravelAgentDetector::detect()->isAgent;
    }

    public static function stdoutIsTty(): bool
    {
        return defined('STDOUT') && stream_isatty(STDOUT);
    }
}

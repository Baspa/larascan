<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

/**
 * Detects whether larascan is running under an AI coding agent
 * (Claude Code, Cursor, Aider, etc.). When true, the CLI should default
 * to machine-readable output (JSON) instead of decorated terminal output.
 */
final class AgentDetector
{
    /**
     * Known env vars set by AI coding agents.
     *
     * @var array<int, string>
     */
    private const AGENT_ENV_VARS = [
        'CLAUDECODE',
        'CLAUDE_CODE',
        'CURSOR_AGENT',
        'AIDER_AUTO_ACCEPT',
        'COPILOT_AGENT_ID',
        'CONTINUE_AGENT',
        'LARASCAN_AGENT_MODE',
    ];

    public static function isAgentRun(): bool
    {
        foreach (self::AGENT_ENV_VARS as $var) {
            $value = getenv($var);
            if ($value !== false && $value !== '') {
                return true;
            }
        }

        return false;
    }

    public static function stdoutIsTty(): bool
    {
        return defined('STDOUT') && stream_isatty(STDOUT);
    }
}

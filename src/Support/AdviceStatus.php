<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

enum AdviceStatus: string
{
    case Surfaced = 'surfaced';
    case NotSurfaced = 'not_surfaced';
    case Skipped = 'skipped';
    case Errored = 'errored';
}

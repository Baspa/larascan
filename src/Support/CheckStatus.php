<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

enum CheckStatus: string
{
    case Passed = 'passed';
    case Failed = 'failed';
    case Skipped = 'skipped';
    case Errored = 'errored';
}

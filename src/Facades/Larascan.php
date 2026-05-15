<?php

declare(strict_types=1);

namespace Baspa\Larascan\Facades;

use Baspa\Larascan\Larascan as LarascanService;
use Baspa\Larascan\Support\ScanOptions;
use Baspa\Larascan\Support\ScanResult;
use Illuminate\Support\Facades\Facade;

/**
 * @method static ScanResult scan(ScanOptions $options = null)
 *
 * @see LarascanService
 */
class Larascan extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return LarascanService::class;
    }
}

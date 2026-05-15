<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tests;

use Baspa\Larascan\LarascanServiceProvider;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    /**
     * @param  Application  $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            LarascanServiceProvider::class,
        ];
    }
}

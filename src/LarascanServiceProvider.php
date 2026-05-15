<?php

declare(strict_types=1);

namespace Baspa\Larascan;

use Baspa\Larascan\Commands\ListChecksCommand;
use Baspa\Larascan\Commands\ScanCommand;
use Baspa\Larascan\Support\CheckRegistry;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class LarascanServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('larascan')
            ->hasConfigFile('larascan')
            ->hasCommand(ScanCommand::class)
            ->hasCommand(ListChecksCommand::class);
        // Additional hasCommand() calls are appended in Task 14.
    }

    public function packageRegistered(): void
    {
        $this->app->singleton(CheckRegistry::class, function (): CheckRegistry {
            /** @var array<string, array{enabled?: bool}> $config */
            $config = $this->app->make('config')->get('larascan.checks', []);

            $registry = new CheckRegistry($config);

            // Checks shipped with this package are registered in later tasks.

            return $registry;
        });

        $this->app->singleton(Larascan::class, function (): Larascan {
            return new Larascan($this->app->make(CheckRegistry::class));
        });
    }
}

<?php

declare(strict_types=1);

namespace Baspa\Larascan;

use Baspa\Larascan\Checks\Config\AppDebugCheck;
use Baspa\Larascan\Checks\Config\AppEnvCheck;
use Baspa\Larascan\Checks\Config\AppKeyCheck;
use Baspa\Larascan\Checks\Config\EnvExampleSyncCheck;
use Baspa\Larascan\Checks\Config\EnvNotCommittedCheck;
use Baspa\Larascan\Checks\Config\LogLevelCheck;
use Baspa\Larascan\Checks\Dependencies\ComposerAuditCheck;
use Baspa\Larascan\Checks\Dependencies\NpmAuditCheck;
use Baspa\Larascan\Commands\InstallCommand;
use Baspa\Larascan\Commands\ListChecksCommand;
use Baspa\Larascan\Commands\ScanCommand;
use Baspa\Larascan\Contracts\Check;
use Baspa\Larascan\Support\CheckRegistry;
use Baspa\Larascan\Tools\ComposerAuditRunner;
use Baspa\Larascan\Tools\NpmAuditRunner;
use Baspa\Larascan\Tools\PhpStanRunner;
use Baspa\Larascan\Tools\SemgrepRunner;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class LarascanServiceProvider extends PackageServiceProvider
{
    /**
     * Checks shipped with this package, in the order they appear in `larascan:list`.
     *
     * @return array<int, class-string<Check>>
     */
    private static function shippedChecks(): array
    {
        return [
            AppDebugCheck::class,
            AppKeyCheck::class,
            AppEnvCheck::class,
            EnvNotCommittedCheck::class,
            EnvExampleSyncCheck::class,
            LogLevelCheck::class,
            ComposerAuditCheck::class,
            NpmAuditCheck::class,
        ];
    }

    public function configurePackage(Package $package): void
    {
        $package
            ->name('larascan')
            ->hasConfigFile('larascan')
            ->hasCommand(ScanCommand::class)
            ->hasCommand(ListChecksCommand::class)
            ->hasCommand(InstallCommand::class);
    }

    public function packageRegistered(): void
    {
        $this->bindRunners();

        $this->app->bind(EnvNotCommittedCheck::class, fn (): EnvNotCommittedCheck => new EnvNotCommittedCheck(
            basePath: $this->app->basePath(),
        ));

        $this->app->bind(EnvExampleSyncCheck::class, fn (): EnvExampleSyncCheck => new EnvExampleSyncCheck(
            basePath: $this->app->basePath(),
        ));

        $this->app->singleton(CheckRegistry::class, function (): CheckRegistry {
            /** @var array<string, array{enabled?: bool}> $config */
            $config = $this->app->make('config')->get('larascan.checks', []);

            $registry = new CheckRegistry($config);

            foreach (self::shippedChecks() as $checkClass) {
                /** @var Check $check */
                $check = $this->app->make($checkClass);
                $registry->register($check);
            }

            return $registry;
        });

        $this->app->singleton(Larascan::class, function (): Larascan {
            return new Larascan($this->app->make(CheckRegistry::class));
        });
    }

    /**
     * Bind the tool runners with config-driven binary paths so the container can
     * auto-resolve consumer Check classes. Bindings re-read config on every
     * `make()` so runtime config changes take effect immediately.
     */
    private function bindRunners(): void
    {
        $this->app->bind(ComposerAuditRunner::class, fn (): ComposerAuditRunner => new ComposerAuditRunner(
            workingDir: $this->app->basePath(),
            binary: $this->resolveToolBinary('composer'),
        ));

        $this->app->bind(NpmAuditRunner::class, fn (): NpmAuditRunner => new NpmAuditRunner(
            workingDir: $this->app->basePath(),
            binary: $this->resolveToolBinary('npm'),
        ));

        $this->app->bind(SemgrepRunner::class, fn (): SemgrepRunner => new SemgrepRunner(
            workingDir: $this->app->basePath(),
            binary: $this->resolveToolBinary('semgrep'),
        ));

        $this->app->bind(PhpStanRunner::class, fn (): PhpStanRunner => new PhpStanRunner(
            workingDir: $this->app->basePath(),
        ));
    }

    private function resolveToolBinary(string $name): string
    {
        $value = $this->app->make('config')->get("larascan.tools.{$name}");

        return is_string($value) && $value !== '' ? $value : $name;
    }
}

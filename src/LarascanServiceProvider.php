<?php

declare(strict_types=1);

namespace Baspa\Larascan;

use Baspa\Larascan\Checks\Auth\BcryptRoundsCheck;
use Baspa\Larascan\Checks\Auth\SanctumExpirationCheck;
use Baspa\Larascan\Checks\Config\AppDebugCheck;
use Baspa\Larascan\Checks\Config\AppEnvCheck;
use Baspa\Larascan\Checks\Config\AppKeyCheck;
use Baspa\Larascan\Checks\Config\DebugBlacklistCheck;
use Baspa\Larascan\Checks\Config\EnvCallsOutsideConfigCheck;
use Baspa\Larascan\Checks\Config\EnvExampleSyncCheck;
use Baspa\Larascan\Checks\Config\EnvNotCommittedCheck;
use Baspa\Larascan\Checks\Config\LogLevelCheck;
use Baspa\Larascan\Checks\Config\TrustedProxiesCheck;
use Baspa\Larascan\Checks\Cookies\EncryptCookiesExcludesCheck;
use Baspa\Larascan\Checks\Cookies\EncryptCookiesMiddlewareCheck;
use Baspa\Larascan\Checks\Cookies\SessionEncryptCheck;
use Baspa\Larascan\Checks\Cookies\SessionHttpOnlyCheck;
use Baspa\Larascan\Checks\Cookies\SessionLifetimeCheck;
use Baspa\Larascan\Checks\Cookies\SessionSameSiteCheck;
use Baspa\Larascan\Checks\Cookies\SessionSecureCheck;
use Baspa\Larascan\Checks\Csrf\CsrfExceptSuspiciousCheck;
use Baspa\Larascan\Checks\Csrf\CsrfMiddlewareDisabledCheck;
use Baspa\Larascan\Checks\Dependencies\ComposerAuditCheck;
use Baspa\Larascan\Checks\Dependencies\NpmAuditCheck;
use Baspa\Larascan\Checks\Headers\CorsWildcardCheck;
use Baspa\Larascan\Checks\Headers\CspDefinedCheck;
use Baspa\Larascan\Checks\Headers\CspUnsafeInlineCheck;
use Baspa\Larascan\Checks\Headers\HstsCheck;
use Baspa\Larascan\Checks\Headers\ReferrerPolicyCheck;
use Baspa\Larascan\Checks\Headers\XContentTypeOptionsCheck;
use Baspa\Larascan\Checks\Headers\XFrameOptionsCheck;
use Baspa\Larascan\Checks\Logging\CustomErrorPagesCheck;
use Baspa\Larascan\Checks\Logging\DdDumpDebugCheck;
use Baspa\Larascan\Checks\Logging\SensitiveInLogContextCheck;
use Baspa\Larascan\Checks\Models\ForceFillUserInputCheck;
use Baspa\Larascan\Checks\Models\ForeignKeyFillableCheck;
use Baspa\Larascan\Checks\Models\UnguardCallCheck;
use Baspa\Larascan\Checks\Models\UnguardedModelCheck;
use Baspa\Larascan\Checks\Php\AllowUrlFopenCheck;
use Baspa\Larascan\Checks\Php\DisplayErrorsCheck;
use Baspa\Larascan\Checks\Php\ExposePhpCheck;
use Baspa\Larascan\Checks\Php\PhpinfoCheck;
use Baspa\Larascan\Checks\Php\PublicSensitiveFilesCheck;
use Baspa\Larascan\Commands\InstallCommand;
use Baspa\Larascan\Commands\ListChecksCommand;
use Baspa\Larascan\Commands\ScanCommand;
use Baspa\Larascan\Contracts\Check;
use Baspa\Larascan\Support\CheckRegistry;
use Baspa\Larascan\Support\FileParser;
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
            EnvCallsOutsideConfigCheck::class,
            DebugBlacklistCheck::class,
            TrustedProxiesCheck::class,
            SessionSecureCheck::class,
            SessionHttpOnlyCheck::class,
            SessionSameSiteCheck::class,
            SessionEncryptCheck::class,
            SessionLifetimeCheck::class,
            EncryptCookiesMiddlewareCheck::class,
            EncryptCookiesExcludesCheck::class,
            CorsWildcardCheck::class,
            HstsCheck::class,
            XContentTypeOptionsCheck::class,
            XFrameOptionsCheck::class,
            ReferrerPolicyCheck::class,
            CspDefinedCheck::class,
            CspUnsafeInlineCheck::class,
            ExposePhpCheck::class,
            DisplayErrorsCheck::class,
            AllowUrlFopenCheck::class,
            PublicSensitiveFilesCheck::class,
            PhpinfoCheck::class,
            BcryptRoundsCheck::class,
            SanctumExpirationCheck::class,
            CsrfMiddlewareDisabledCheck::class,
            CsrfExceptSuspiciousCheck::class,
            UnguardedModelCheck::class,
            UnguardCallCheck::class,
            ForeignKeyFillableCheck::class,
            ForceFillUserInputCheck::class,
            DdDumpDebugCheck::class,
            CustomErrorPagesCheck::class,
            SensitiveInLogContextCheck::class,
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

        $this->app->bind(EnvCallsOutsideConfigCheck::class, fn (): EnvCallsOutsideConfigCheck => new EnvCallsOutsideConfigCheck(
            basePath: $this->app->basePath(),
            parser: new FileParser,
        ));

        $this->app->bind(PublicSensitiveFilesCheck::class, fn (): PublicSensitiveFilesCheck => new PublicSensitiveFilesCheck(
            publicPath: $this->app->publicPath(),
        ));

        $this->app->bind(PhpinfoCheck::class, fn (): PhpinfoCheck => new PhpinfoCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(UnguardedModelCheck::class, fn (): UnguardedModelCheck => new UnguardedModelCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(UnguardCallCheck::class, fn (): UnguardCallCheck => new UnguardCallCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(ForeignKeyFillableCheck::class, fn (): ForeignKeyFillableCheck => new ForeignKeyFillableCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(ForceFillUserInputCheck::class, fn (): ForceFillUserInputCheck => new ForceFillUserInputCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(DdDumpDebugCheck::class, fn (): DdDumpDebugCheck => new DdDumpDebugCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(CustomErrorPagesCheck::class, fn (): CustomErrorPagesCheck => new CustomErrorPagesCheck(
            basePath: $this->app->basePath(),
        ));

        $this->app->bind(SensitiveInLogContextCheck::class, fn (): SensitiveInLogContextCheck => new SensitiveInLogContextCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
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

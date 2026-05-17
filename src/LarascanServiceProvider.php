<?php

declare(strict_types=1);

namespace Baspa\Larascan;

use Baspa\Larascan\Advices\Auth\PasswordResetMfaAdvice;
use Baspa\Larascan\Advices\Auth\SignedUrlUserContextAdvice;
use Baspa\Larascan\Advices\Config\ConfigValidatedAtBootAdvice;
use Baspa\Larascan\Advices\Crypto\StagingKeyInProductionAdvice;
use Baspa\Larascan\Advices\Dependencies\OutdatedPackagesAdvice;
use Baspa\Larascan\Advices\Routing\BroadcastChannelsFlagsAdvice;
use Baspa\Larascan\Advices\Xss\LivewirePublicPropertiesAdvice;
use Baspa\Larascan\Checks\Auth\ApiAbilityScopingCheck;
use Baspa\Larascan\Checks\Auth\BcryptRoundsCheck;
use Baspa\Larascan\Checks\Auth\JwtMissingExpirationCheck;
use Baspa\Larascan\Checks\Auth\LoginThrottleCheck;
use Baspa\Larascan\Checks\Auth\OtpRateLimitingCheck;
use Baspa\Larascan\Checks\Auth\PasswordColumnPlainCheck;
use Baspa\Larascan\Checks\Auth\RegistrationRateLimitCheck;
use Baspa\Larascan\Checks\Auth\SanctumExpirationCheck;
use Baspa\Larascan\Checks\Auth\SignedRoutesVerifyCheck;
use Baspa\Larascan\Checks\Auth\SignedUrlNoParamsCheck;
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
use Baspa\Larascan\Checks\Crypto\CipherNotPinnedCheck;
use Baspa\Larascan\Checks\Crypto\HardcodedSecretCheck;
use Baspa\Larascan\Checks\Crypto\PasswordSelfGeneratedCheck;
use Baspa\Larascan\Checks\Crypto\WeakHashCheck;
use Baspa\Larascan\Checks\Crypto\WeakRandomCheck;
use Baspa\Larascan\Checks\Csrf\CsrfExceptSuspiciousCheck;
use Baspa\Larascan\Checks\Csrf\CsrfMiddlewareDisabledCheck;
use Baspa\Larascan\Checks\Dependencies\ComposerAuditCheck;
use Baspa\Larascan\Checks\Dependencies\MinimumStabilityDevCheck;
use Baspa\Larascan\Checks\Dependencies\NpmAuditCheck;
use Baspa\Larascan\Checks\Dependencies\OutdatedPhpCheck;
use Baspa\Larascan\Checks\Files\PathTraversalCheck;
use Baspa\Larascan\Checks\Files\PublicExecutableUploadsCheck;
use Baspa\Larascan\Checks\Files\UnlinkUserInputCheck;
use Baspa\Larascan\Checks\Files\UploadMimesValidationCheck;
use Baspa\Larascan\Checks\Headers\CorsWildcardCheck;
use Baspa\Larascan\Checks\Headers\CspBaseUriCheck;
use Baspa\Larascan\Checks\Headers\CspDefinedCheck;
use Baspa\Larascan\Checks\Headers\CspUnsafeInlineCheck;
use Baspa\Larascan\Checks\Headers\HstsCheck;
use Baspa\Larascan\Checks\Headers\ReferrerPolicyCheck;
use Baspa\Larascan\Checks\Headers\XContentTypeOptionsCheck;
use Baspa\Larascan\Checks\Headers\XFrameOptionsCheck;
use Baspa\Larascan\Checks\Injection\CommandInjectionCheck;
use Baspa\Larascan\Checks\Injection\HostHeaderCheck;
use Baspa\Larascan\Checks\Injection\OpenRedirectCheck;
use Baspa\Larascan\Checks\Injection\ProcessShellCheck;
use Baspa\Larascan\Checks\Injection\UnserializeCheck;
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
use Baspa\Larascan\Checks\Repo\DebugToolbarsCheck;
use Baspa\Larascan\Checks\Repo\DependabotCheck;
use Baspa\Larascan\Checks\Repo\GitleaksHistoryCheck;
use Baspa\Larascan\Checks\Repo\SecurityTxtCheck;
use Baspa\Larascan\Checks\Routing\ApiHttpOnlyCheck;
use Baspa\Larascan\Checks\Routing\StateMutatingGetCheck;
use Baspa\Larascan\Checks\Sql\OrWhereScopeBypassCheck;
use Baspa\Larascan\Checks\Sql\SqlRawOrderByCheck;
use Baspa\Larascan\Checks\Sql\SqlRawUserInputCheck;
use Baspa\Larascan\Checks\Sql\SqlValidationRuleInjectionCheck;
use Baspa\Larascan\Checks\Sql\SqlVariableTableColumnCheck;
use Baspa\Larascan\Checks\Xss\BladeUnescapedCheck;
use Baspa\Larascan\Checks\Xss\HtmlStringCastCheck;
use Baspa\Larascan\Checks\Xss\HtmlStringCheck;
use Baspa\Larascan\Checks\Xss\UrlJavascriptProtocolCheck;
use Baspa\Larascan\Commands\AdviseCommand;
use Baspa\Larascan\Commands\InstallCommand;
use Baspa\Larascan\Commands\ListChecksCommand;
use Baspa\Larascan\Commands\ScanCommand;
use Baspa\Larascan\Contracts\Advice;
use Baspa\Larascan\Contracts\Check;
use Baspa\Larascan\Reporters\AdviceConsoleReporter;
use Baspa\Larascan\Support\AdviceRegistry;
use Baspa\Larascan\Support\CheckRegistry;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Tools\ComposerAuditRunner;
use Baspa\Larascan\Tools\ComposerOutdatedRunner;
use Baspa\Larascan\Tools\NpmAuditRunner;
use Baspa\Larascan\Tools\NpmOutdatedRunner;
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
            CspBaseUriCheck::class,
            ExposePhpCheck::class,
            DisplayErrorsCheck::class,
            AllowUrlFopenCheck::class,
            PublicSensitiveFilesCheck::class,
            PhpinfoCheck::class,
            BcryptRoundsCheck::class,
            SanctumExpirationCheck::class,
            JwtMissingExpirationCheck::class,
            CsrfMiddlewareDisabledCheck::class,
            CsrfExceptSuspiciousCheck::class,
            StateMutatingGetCheck::class,
            ApiHttpOnlyCheck::class,
            UnguardedModelCheck::class,
            UnguardCallCheck::class,
            ForeignKeyFillableCheck::class,
            ForceFillUserInputCheck::class,
            DdDumpDebugCheck::class,
            CustomErrorPagesCheck::class,
            SensitiveInLogContextCheck::class,
            DependabotCheck::class,
            GitleaksHistoryCheck::class,
            DebugToolbarsCheck::class,
            SecurityTxtCheck::class,
            LoginThrottleCheck::class,
            OtpRateLimitingCheck::class,
            RegistrationRateLimitCheck::class,
            PasswordColumnPlainCheck::class,
            SignedRoutesVerifyCheck::class,
            SignedUrlNoParamsCheck::class,
            ApiAbilityScopingCheck::class,
            WeakHashCheck::class,
            WeakRandomCheck::class,
            CipherNotPinnedCheck::class,
            HardcodedSecretCheck::class,
            PasswordSelfGeneratedCheck::class,
            CommandInjectionCheck::class,
            ProcessShellCheck::class,
            UnserializeCheck::class,
            OpenRedirectCheck::class,
            HostHeaderCheck::class,
            BladeUnescapedCheck::class,
            HtmlStringCheck::class,
            HtmlStringCastCheck::class,
            UrlJavascriptProtocolCheck::class,
            PathTraversalCheck::class,
            UnlinkUserInputCheck::class,
            UploadMimesValidationCheck::class,
            PublicExecutableUploadsCheck::class,
            SqlRawUserInputCheck::class,
            SqlRawOrderByCheck::class,
            SqlVariableTableColumnCheck::class,
            SqlValidationRuleInjectionCheck::class,
            OrWhereScopeBypassCheck::class,
            ComposerAuditCheck::class,
            NpmAuditCheck::class,
            MinimumStabilityDevCheck::class,
            OutdatedPhpCheck::class,
        ];
    }

    /**
     * @return array<int, class-string<Advice>>
     */
    private static function shippedAdvices(): array
    {
        return [
            SignedUrlUserContextAdvice::class,
            PasswordResetMfaAdvice::class,
            BroadcastChannelsFlagsAdvice::class,
            OutdatedPackagesAdvice::class,
            ConfigValidatedAtBootAdvice::class,
            LivewirePublicPropertiesAdvice::class,
            StagingKeyInProductionAdvice::class,
        ];
    }

    public function configurePackage(Package $package): void
    {
        $package
            ->name('larascan')
            ->hasConfigFile('larascan')
            ->hasCommand(ScanCommand::class)
            ->hasCommand(ListChecksCommand::class)
            ->hasCommand(InstallCommand::class)
            ->hasCommand(AdviseCommand::class);
    }

    public function packageBooted(): void
    {
        $this->publishes([
            __DIR__.'/../resources/stubs/workflow.yml.stub' => base_path('.github/workflows/larascan.yml'),
        ], 'larascan-workflow');
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

        $this->app->bind(DependabotCheck::class, fn (): DependabotCheck => new DependabotCheck(
            basePath: $this->app->basePath(),
        ));

        $this->app->bind(GitleaksHistoryCheck::class, fn (): GitleaksHistoryCheck => new GitleaksHistoryCheck(
            basePath: $this->app->basePath(),
        ));

        $this->app->bind(DebugToolbarsCheck::class, fn (): DebugToolbarsCheck => new DebugToolbarsCheck(
            basePath: $this->app->basePath(),
        ));

        $this->app->bind(SecurityTxtCheck::class, fn (): SecurityTxtCheck => new SecurityTxtCheck(
            publicPath: $this->app->publicPath(),
        ));

        $this->app->bind(PasswordColumnPlainCheck::class, fn (): PasswordColumnPlainCheck => new PasswordColumnPlainCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(ApiAbilityScopingCheck::class, fn (): ApiAbilityScopingCheck => new ApiAbilityScopingCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(SignedUrlNoParamsCheck::class, fn (): SignedUrlNoParamsCheck => new SignedUrlNoParamsCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(WeakHashCheck::class, fn (): WeakHashCheck => new WeakHashCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(WeakRandomCheck::class, fn (): WeakRandomCheck => new WeakRandomCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(CipherNotPinnedCheck::class, fn (): CipherNotPinnedCheck => new CipherNotPinnedCheck(
            configPath: $this->app->configPath(),
        ));

        $this->app->bind(HardcodedSecretCheck::class, fn (): HardcodedSecretCheck => new HardcodedSecretCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(PasswordSelfGeneratedCheck::class, fn (): PasswordSelfGeneratedCheck => new PasswordSelfGeneratedCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(CommandInjectionCheck::class, fn (): CommandInjectionCheck => new CommandInjectionCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(ProcessShellCheck::class, fn (): ProcessShellCheck => new ProcessShellCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(UnserializeCheck::class, fn (): UnserializeCheck => new UnserializeCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(OpenRedirectCheck::class, fn (): OpenRedirectCheck => new OpenRedirectCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(BladeUnescapedCheck::class, fn (): BladeUnescapedCheck => new BladeUnescapedCheck(
            viewsPath: $this->app->basePath('resources/views'),
        ));

        $this->app->bind(HtmlStringCheck::class, fn (): HtmlStringCheck => new HtmlStringCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(HtmlStringCastCheck::class, fn (): HtmlStringCastCheck => new HtmlStringCastCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(UrlJavascriptProtocolCheck::class, fn (): UrlJavascriptProtocolCheck => new UrlJavascriptProtocolCheck(
            viewsPath: $this->app->basePath('resources/views'),
        ));

        $this->app->bind(PathTraversalCheck::class, fn (): PathTraversalCheck => new PathTraversalCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(UnlinkUserInputCheck::class, fn (): UnlinkUserInputCheck => new UnlinkUserInputCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(UploadMimesValidationCheck::class, fn (): UploadMimesValidationCheck => new UploadMimesValidationCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(PublicExecutableUploadsCheck::class, fn (): PublicExecutableUploadsCheck => new PublicExecutableUploadsCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
            publicPath: $this->app->publicPath(),
        ));

        $this->app->bind(SqlRawUserInputCheck::class, fn (): SqlRawUserInputCheck => new SqlRawUserInputCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(SqlRawOrderByCheck::class, fn (): SqlRawOrderByCheck => new SqlRawOrderByCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(SqlVariableTableColumnCheck::class, fn (): SqlVariableTableColumnCheck => new SqlVariableTableColumnCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(SqlValidationRuleInjectionCheck::class, fn (): SqlValidationRuleInjectionCheck => new SqlValidationRuleInjectionCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(OrWhereScopeBypassCheck::class, fn (): OrWhereScopeBypassCheck => new OrWhereScopeBypassCheck(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(MinimumStabilityDevCheck::class, fn (): MinimumStabilityDevCheck => new MinimumStabilityDevCheck(
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

        $this->app->bind(SignedUrlUserContextAdvice::class, fn (): SignedUrlUserContextAdvice => new SignedUrlUserContextAdvice(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(BroadcastChannelsFlagsAdvice::class, fn (): BroadcastChannelsFlagsAdvice => new BroadcastChannelsFlagsAdvice(
            basePath: $this->app->basePath(),
            parser: new FileParser,
        ));

        $this->app->bind(OutdatedPackagesAdvice::class, fn (): OutdatedPackagesAdvice => new OutdatedPackagesAdvice(
            composer: $this->app->make(ComposerOutdatedRunner::class),
            npm: $this->app->make(NpmOutdatedRunner::class),
        ));

        $this->app->bind(ConfigValidatedAtBootAdvice::class, fn (): ConfigValidatedAtBootAdvice => new ConfigValidatedAtBootAdvice(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(LivewirePublicPropertiesAdvice::class, fn (): LivewirePublicPropertiesAdvice => new LivewirePublicPropertiesAdvice(
            appPath: $this->app->basePath('app'),
            parser: new FileParser,
        ));

        $this->app->bind(StagingKeyInProductionAdvice::class, fn (): StagingKeyInProductionAdvice => new StagingKeyInProductionAdvice(
            basePath: $this->app->basePath(),
        ));

        $this->app->singleton(AdviceRegistry::class, function (): AdviceRegistry {
            /** @var array<string, array{enabled?: bool}> $config */
            $config = $this->app->make('config')->get('larascan.advices', []);
            $registry = new AdviceRegistry($config);

            foreach (self::shippedAdvices() as $adviceClass) {
                /** @var Advice $advice */
                $advice = $this->app->make($adviceClass);
                $registry->register($advice);
            }

            return $registry;
        });

        $this->app->singleton(Advise::class, function (): Advise {
            return new Advise($this->app->make(AdviceRegistry::class));
        });

        $this->app->singleton(AdviceConsoleReporter::class, fn (): AdviceConsoleReporter => new AdviceConsoleReporter);
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

        $this->app->bind(ComposerOutdatedRunner::class, fn (): ComposerOutdatedRunner => new ComposerOutdatedRunner(
            workingDir: $this->app->basePath(),
            binary: $this->resolveToolBinary('composer'),
        ));

        $this->app->bind(NpmOutdatedRunner::class, fn (): NpmOutdatedRunner => new NpmOutdatedRunner(
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

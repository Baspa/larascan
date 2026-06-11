<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Ecosystem;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\GateDefinitionIntrospection;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;

final class HorizonGateCheck extends AbstractCheck
{
    public function __construct(
        private readonly string $basePath,
        private readonly FileParser $parser,
        private readonly Application $app,
    ) {}

    public function id(): string
    {
        return 'ecosystem.horizon-gate';
    }

    public function category(): Category
    {
        return Category::Ecosystem;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'Horizon viewHorizon gate must not be trivially true';
    }

    public function isApplicable(): bool
    {
        return class_exists('Laravel\\Horizon\\Horizon');
    }

    /**
     * Horizon denies non-local access by default, so a missing gate is not the
     * bug — a trivially-true gate is.
     *
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        $providerFiles = glob($this->basePath.'/app/Providers/*.php');
        if ($providerFiles === false) {
            $providerFiles = [];
        }
        sort($providerFiles);

        $introspection = new GateDefinitionIntrospection($this->parser);
        $trivialGate = $introspection->findTriviallyTrueGate($providerFiles, 'viewHorizon');

        if ($trivialGate !== null) {
            yield new Finding(
                checkId: $this->id(),
                severity: Severity::Critical,
                message: "Gate::define('viewHorizon', ...) returns true unconditionally — the Horizon dashboard (jobs, payloads, failures) is open to anyone. Restrict the gate to specific users.",
                file: str_replace($this->basePath.DIRECTORY_SEPARATOR, '', $trivialGate['file']),
                line: $trivialGate['line'],
            );

            return;
        }

        /** @var Repository $config */
        $config = $this->app->make('config');
        /** @var Gate $gate */
        $gate = $this->app->make(Gate::class);

        if (! $gate->has('viewHorizon') && $config->get('app.env') === 'production') {
            yield new Finding(
                checkId: $this->id(),
                severity: Severity::Info,
                message: 'No viewHorizon gate is defined — the Horizon dashboard is locked to the local environment by default. Define the gate to make dashboard access an intentional decision.',
            );
        }
    }
}

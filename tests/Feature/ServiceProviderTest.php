<?php

declare(strict_types=1);

use Baspa\Larascan\Larascan;
use Baspa\Larascan\Support\CheckRegistry;
use Baspa\Larascan\Tools\ComposerAuditRunner;

it('boots the Larascan service from the container', function () {
    expect($this->app->make(Larascan::class))->toBeInstanceOf(Larascan::class);
});

it('registers all shipped checks via the array-driven provider', function () {
    /** @var CheckRegistry $registry */
    $registry = $this->app->make(CheckRegistry::class);

    $ids = array_map(fn ($c) => $c->id(), $registry->all());

    expect($ids)->toContain('config.app-debug')
        ->and($ids)->toContain('dependencies.composer-audit')
        ->and($ids)->toContain('dependencies.npm-audit');
});

it('uses the configured composer binary in the bound runner', function () {
    config()->set('larascan.tools.composer', '/opt/bin/composer-custom');

    $runner = $this->app->make(ComposerAuditRunner::class);

    $reflection = new ReflectionClass($runner);
    $prop = $reflection->getProperty('binary');
    expect($prop->getValue($runner))->toBe('/opt/bin/composer-custom');
});

it('registers exactly 70 checks after Phase 9a — all spec checks live', function () {
    /** @var CheckRegistry $registry */
    $registry = $this->app->make(CheckRegistry::class);
    expect(count($registry->all()))->toBe(70);
});

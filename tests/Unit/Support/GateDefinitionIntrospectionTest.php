<?php

declare(strict_types=1);

use Baspa\Larascan\Support\FileParser;
use Baspa\Larascan\Support\GateDefinitionIntrospection;

function gateFixture(string $set, string $provider): string
{
    return __DIR__.'/../../Fixtures/Providers/'.$set.'/app/Providers/'.$provider.'.php';
}

it('finds a trivially-true gate written as a closure returning true', function () {
    $introspection = new GateDefinitionIntrospection(new FileParser);

    $result = $introspection->findTriviallyTrueGate(
        [gateFixture('trivial-gate', 'HorizonServiceProvider')],
        'viewHorizon',
    );

    expect($result)->not->toBeNull()
        ->and($result['file'])->toBe(gateFixture('trivial-gate', 'HorizonServiceProvider'))
        ->and($result['line'])->toBe(12);
});

it('finds a trivially-true gate written as an arrow function', function () {
    $introspection = new GateDefinitionIntrospection(new FileParser);

    $result = $introspection->findTriviallyTrueGate(
        [gateFixture('trivial-gate', 'PulseServiceProvider')],
        'viewPulse',
    );

    expect($result)->not->toBeNull()
        ->and($result['line'])->toBe(12);
});

it('does not judge gates with real logic', function () {
    $introspection = new GateDefinitionIntrospection(new FileParser);

    expect($introspection->findTriviallyTrueGate(
        [gateFixture('legit-gate', 'HorizonServiceProvider')],
        'viewHorizon',
    ))->toBeNull()
        ->and($introspection->findTriviallyTrueGate(
            [gateFixture('legit-gate', 'PulseServiceProvider')],
            'viewPulse',
        ))->toBeNull();
});

it('finds a trivially-true gate defined via the fully-qualified Gate facade', function () {
    $introspection = new GateDefinitionIntrospection(new FileParser);

    $result = $introspection->findTriviallyTrueGate(
        [gateFixture('fqcn-gate', 'HorizonServiceProvider')],
        'viewHorizon',
    );

    expect($result)->not->toBeNull()
        ->and($result['file'])->toBe(gateFixture('fqcn-gate', 'HorizonServiceProvider'))
        ->and($result['line'])->toBe(11);
});

it('skips an unparseable provider file without error', function () {
    $introspection = new GateDefinitionIntrospection(new FileParser);

    expect($introspection->findTriviallyTrueGate(
        [gateFixture('syntax-error', 'HorizonServiceProvider')],
        'viewHorizon',
    ))->toBeNull();
});

it('returns null when the gate name does not match', function () {
    $introspection = new GateDefinitionIntrospection(new FileParser);

    expect($introspection->findTriviallyTrueGate(
        [gateFixture('trivial-gate', 'HorizonServiceProvider')],
        'viewTelescope',
    ))->toBeNull();
});

it('returns null for missing files', function () {
    $introspection = new GateDefinitionIntrospection(new FileParser);

    expect($introspection->findTriviallyTrueGate(
        ['/nonexistent/app/Providers/HorizonServiceProvider.php'],
        'viewHorizon',
    ))->toBeNull();
});

it('scans multiple provider files and skips missing ones', function () {
    $introspection = new GateDefinitionIntrospection(new FileParser);

    $result = $introspection->findTriviallyTrueGate(
        [
            gateFixture('trivial-gate-app', 'PulseServiceProvider'), // does not exist
            gateFixture('trivial-gate-app', 'AppServiceProvider'),
        ],
        'viewPulse',
    );

    expect($result)->not->toBeNull()
        ->and($result['file'])->toBe(gateFixture('trivial-gate-app', 'AppServiceProvider'));
});

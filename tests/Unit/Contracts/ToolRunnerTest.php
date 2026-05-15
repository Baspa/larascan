<?php

declare(strict_types=1);

use Baspa\Larascan\Contracts\ToolRunner;

it('exists as an interface', function () {
    expect(interface_exists(ToolRunner::class))->toBeTrue();
});

it('declares isAvailable returning bool', function () {
    $reflection = new ReflectionClass(ToolRunner::class);
    $method = $reflection->getMethod('isAvailable');
    expect($method->getReturnType()?->__toString())->toBe('bool');
});

<?php

declare(strict_types=1);

use Baspa\Larascan\Support\Category;

it('exposes the eighteen categories', function () {
    expect(Category::cases())->toHaveCount(18);
});

it('exposes human labels', function () {
    expect(Category::Cookies->label())->toBe('Cookies & sessions')
        ->and(Category::Headers->label())->toBe('HTTP headers');
});

it('has a Routing category with the expected label', function () {
    expect(Category::Routing->value)->toBe('routing')
        ->and(Category::Routing->label())->toBe('Routing');
});

it('has an Ecosystem category with the expected label', function () {
    expect(Category::Ecosystem->value)->toBe('ecosystem')
        ->and(Category::Ecosystem->label())->toBe('Ecosystem packages');
});

it('has a Probe category with the expected label', function () {
    expect(Category::Probe->value)->toBe('probe')
        ->and(Category::Probe->label())->toBe('Runtime probe');
});

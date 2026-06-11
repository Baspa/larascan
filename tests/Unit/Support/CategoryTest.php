<?php

declare(strict_types=1);

use Baspa\Larascan\Support\Category;

it('exposes the seventeen categories', function () {
    expect(Category::cases())->toHaveCount(17);
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

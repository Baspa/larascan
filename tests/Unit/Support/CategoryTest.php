<?php

declare(strict_types=1);

use Baspa\Larascan\Support\Category;

it('exposes the sixteen categories', function () {
    expect(Category::cases())->toHaveCount(16);
});

it('exposes human labels', function () {
    expect(Category::Cookies->label())->toBe('Cookies & sessions')
        ->and(Category::Headers->label())->toBe('HTTP headers');
});

it('has a Routing category with the expected label', function () {
    expect(Category::Routing->value)->toBe('routing')
        ->and(Category::Routing->label())->toBe('Routing');
});

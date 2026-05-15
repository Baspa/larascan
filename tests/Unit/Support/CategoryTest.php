<?php

declare(strict_types=1);

use Baspa\Larascan\Support\Category;

it('exposes the fifteen categories', function () {
    expect(Category::cases())->toHaveCount(15);
});

it('exposes human labels', function () {
    expect(Category::Cookies->label())->toBe('Cookies & sessions')
        ->and(Category::Headers->label())->toBe('HTTP headers');
});

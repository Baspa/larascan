<?php

declare(strict_types=1);

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\CheckRegistry;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;

final class FakeCheck extends AbstractCheck
{
    public function __construct(
        private string $id,
        private Category $category,
        private Severity $severity = Severity::Medium,
    ) {}

    public function id(): string
    {
        return $this->id;
    }

    public function category(): Category
    {
        return $this->category;
    }

    public function severity(): Severity
    {
        return $this->severity;
    }

    public function name(): string
    {
        return 'fake';
    }

    /** @return iterable<Finding> */
    public function run(): iterable
    {
        return [];
    }
}

it('registers and lists checks', function () {
    $registry = new CheckRegistry;
    $registry->register(new FakeCheck('config.a', Category::Config));
    $registry->register(new FakeCheck('cookies.b', Category::Cookies));

    expect($registry->all())->toHaveCount(2);
});

it('filters checks by ID pattern with wildcard', function () {
    $registry = new CheckRegistry;
    $registry->register(new FakeCheck('cookies.a', Category::Cookies));
    $registry->register(new FakeCheck('cookies.b', Category::Cookies));
    $registry->register(new FakeCheck('config.x', Category::Config));

    $matched = iterator_to_array($registry->matching(['cookies.*']));
    expect($matched)->toHaveCount(2);
});

it('filters checks by category', function () {
    $registry = new CheckRegistry;
    $registry->register(new FakeCheck('config.a', Category::Config));
    $registry->register(new FakeCheck('headers.b', Category::Headers));

    $matched = iterator_to_array($registry->forCategory(Category::Headers));
    expect($matched)->toHaveCount(1);
});

it('honors enabled config to exclude checks', function () {
    $registry = new CheckRegistry(config: [
        'cookies.b' => ['enabled' => false],
    ]);
    $registry->register(new FakeCheck('cookies.a', Category::Cookies));
    $registry->register(new FakeCheck('cookies.b', Category::Cookies));

    expect($registry->enabled())->toHaveCount(1);
});

it('throws on duplicate registration', function () {
    $registry = new CheckRegistry;
    $registry->register(new FakeCheck('a', Category::Config));

    expect(fn () => $registry->register(new FakeCheck('a', Category::Config)))
        ->toThrow(InvalidArgumentException::class, 'already registered');
});

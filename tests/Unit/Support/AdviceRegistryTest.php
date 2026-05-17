<?php

declare(strict_types=1);

use Baspa\Larascan\Contracts\Advice;
use Baspa\Larascan\Support\AdviceOutcome;
use Baspa\Larascan\Support\AdviceRegistry;
use Baspa\Larascan\Support\Category;

function makeAdvice(string $id, Category $cat = Category::Auth): Advice
{
    return new class($id, $cat) implements Advice
    {
        public function __construct(private string $idValue, private Category $cat) {}

        public function id(): string
        {
            return $this->idValue;
        }

        public function category(): Category
        {
            return $this->cat;
        }

        public function name(): string
        {
            return 'test';
        }

        public function isApplicable(): bool
        {
            return true;
        }

        public function docsUrl(): string
        {
            return 'https://example.test';
        }

        public function run(): AdviceOutcome
        {
            return AdviceOutcome::notSurfaced();
        }
    };
}

it('registers advices and returns them', function () {
    $registry = new AdviceRegistry;
    $a = makeAdvice('advise.foo');
    $b = makeAdvice('advise.bar');

    $registry->register($a);
    $registry->register($b);

    expect($registry->all())->toHaveCount(2);
});

it('throws when registering an advice with a duplicate id', function () {
    $registry = new AdviceRegistry;
    $registry->register(makeAdvice('advise.foo'));

    expect(fn () => $registry->register(makeAdvice('advise.foo')))
        ->toThrow(InvalidArgumentException::class);
});

it('returns enabled advices honoring config', function () {
    $registry = new AdviceRegistry([
        'advise.bar' => ['enabled' => false],
    ]);
    $registry->register(makeAdvice('advise.foo'));
    $registry->register(makeAdvice('advise.bar'));

    expect($registry->enabled())->toHaveCount(1)
        ->and($registry->enabled()[0]->id())->toBe('advise.foo');
});

it('filters by id pattern', function () {
    $registry = new AdviceRegistry;
    $registry->register(makeAdvice('advise.auth.signed-url'));
    $registry->register(makeAdvice('advise.dependencies.outdated'));

    $matched = iterator_to_array($registry->matching(['advise.auth.*']));
    expect($matched)->toHaveCount(1)
        ->and($matched[0]->id())->toBe('advise.auth.signed-url');
});

it('filters by category', function () {
    $registry = new AdviceRegistry;
    $registry->register(makeAdvice('advise.foo', Category::Auth));
    $registry->register(makeAdvice('advise.bar', Category::Crypto));

    $matched = iterator_to_array($registry->forCategory(Category::Auth));
    expect($matched)->toHaveCount(1)
        ->and($matched[0]->id())->toBe('advise.foo');
});

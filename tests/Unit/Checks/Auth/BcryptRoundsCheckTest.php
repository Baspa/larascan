<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Auth\BcryptRoundsCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new BcryptRoundsCheck($this->app);

    expect($check->id())->toBe('auth.bcrypt-rounds')
        ->and($check->category())->toBe(Category::Auth)
        ->and($check->severity())->toBe(Severity::Medium)
        ->and($check->docsUrl())->toBe('https://github.com/baspa/larascan/blob/main/docs/checks/auth/bcrypt-rounds.md');
});

it('passes when bcrypt rounds is 12', function () {
    config()->set('hashing.bcrypt.rounds', 12);

    $findings = iterator_to_array((new BcryptRoundsCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails when bcrypt rounds is 10', function () {
    config()->set('hashing.bcrypt.rounds', 10);

    $findings = iterator_to_array((new BcryptRoundsCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->checkId)->toBe('auth.bcrypt-rounds')
        ->and($findings[0]->message)->toContain('10')
        ->and($findings[0]->message)->toContain('minimum of 12');
});

it('passes when bcrypt rounds is 14', function () {
    config()->set('hashing.bcrypt.rounds', 14);

    $findings = iterator_to_array((new BcryptRoundsCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

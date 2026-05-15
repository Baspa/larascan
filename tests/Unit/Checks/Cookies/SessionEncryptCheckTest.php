<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Cookies\SessionEncryptCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;

it('exposes correct metadata', function () {
    $check = new SessionEncryptCheck($this->app);

    expect($check->id())->toBe('cookies.session-encrypt')
        ->and($check->category())->toBe(Category::Cookies)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when session.encrypt is true', function () {
    config()->set('session.encrypt', true);
    expect(iterator_to_array((new SessionEncryptCheck($this->app))->run()))->toBeEmpty();
});

it('fails when session.encrypt is false', function () {
    config()->set('session.encrypt', false);
    $findings = iterator_to_array((new SessionEncryptCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High);
});

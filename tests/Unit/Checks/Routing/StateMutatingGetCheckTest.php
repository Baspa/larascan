<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Routing\StateMutatingGetCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Illuminate\Support\Facades\Route;

it('exposes correct metadata', function () {
    $check = new StateMutatingGetCheck($this->app);

    expect($check->id())->toBe('routing.state-mutating-get')
        ->and($check->category())->toBe(Category::Routing)
        ->and($check->severity())->toBe(Severity::High);
});

it('passes when no GET routes invoke state-mutating method names', function () {
    Route::get('/users', 'App\\Http\\Controllers\\UserController@index');

    $findings = iterator_to_array((new StateMutatingGetCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails when a GET route invokes destroy', function () {
    Route::get('/users/{id}/delete', 'App\\Http\\Controllers\\UserController@destroy');

    $findings = iterator_to_array((new StateMutatingGetCheck($this->app))->run());

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->checkId)->toBe('routing.state-mutating-get')
        ->and($findings[0]->message)->toContain('destroy');
});

it('fails when GET route invokes deactivate', function () {
    Route::get('/users/{id}/disable', 'App\\Http\\Controllers\\UserController@deactivate');

    $findings = iterator_to_array((new StateMutatingGetCheck($this->app))->run());

    expect($findings)->toHaveCount(1);
});

it('passes when DELETE route uses destroy (correct verb)', function () {
    Route::delete('/users/{id}', 'App\\Http\\Controllers\\UserController@destroy');

    $findings = iterator_to_array((new StateMutatingGetCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

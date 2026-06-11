<?php

namespace App\Providers;

class HorizonServiceProvider
{
    public function boot(): void
    {
        Gate::define('viewHorizon', fn () => true // missing closing parenthesis and brace

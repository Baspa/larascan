<?php

namespace App\Providers;

use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;

class AuthServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        Gate::define('viewHorizon', fn () => true);
        Gate::define('viewPulse', fn () => true);
    }
}

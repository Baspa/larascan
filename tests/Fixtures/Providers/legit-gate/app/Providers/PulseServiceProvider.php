<?php

namespace App\Providers;

use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;

class PulseServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        Gate::define('viewPulse', fn ($user) => $user->isAdmin());
    }
}

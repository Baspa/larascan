<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;

class HorizonServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        \Illuminate\Support\Facades\Gate::define('viewHorizon', fn () => true);
    }
}

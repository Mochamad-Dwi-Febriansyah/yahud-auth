<?php

namespace Brian\YahudAuth;

use Illuminate\Support\ServiceProvider;

class AuthServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $configPath = function_exists('config_path') ? config_path('jwt.php') : base_path('config/jwt.php');

        $this->publishes([
            __DIR__ . '/../config/jwt.php' => $configPath,
        ], 'config');

        $this->loadRoutesFrom(__DIR__ . '/routes.php');
    }

    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/jwt.php', 'jwt');
    }
}

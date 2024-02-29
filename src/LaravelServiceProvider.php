<?php

namespace Kostyap\JwtAuth;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;

class LaravelServiceProvider extends ServiceProvider
{
    public const CONFIG_NAME = 'jwt.php';

    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../config/config.php' => config_path(self::CONFIG_NAME),
            'config'
        ]);

        $this->extendAuthGuard();
    }

    protected function extendAuthGuard(): void
    {
        Auth::extend('jwt', function (Application $app, string $name, array $config) {
            return new JWTGuard(
                $app->make(JWT::class),
                Auth::createUserProvider($config['provider']),
            );
        });
    }
}
<?php

namespace Kostyap\JwtAuth\Providers;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Kostyap\JwtAuth\Helpers\TokenRequestGetter;
use Kostyap\JwtAuth\Jwt\Generation\JWTGenerator;
use Kostyap\JwtAuth\Jwt\Parsing\JWTParser;
use Kostyap\JwtAuth\Jwt\Validation\JWTValidator;
use Kostyap\JwtAuth\RefreshToken\Repository\DatabaseRefreshSessionRepository;
use Kostyap\JwtAuth\RefreshToken\Repository\RefreshSessionRepository;
use Kostyap\JwtAuth\RefreshToken\TokenRefresher;

class JwtAuthServiceProvider extends ServiceProvider
{
    public const CONFIG_NAME = 'jwt.php';

    public array $bindings = [
        RefreshSessionRepository::class => DatabaseRefreshSessionRepository::class
    ];

    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../../config/config.php' => config_path(self::CONFIG_NAME)
        ]);
        $this->loadMigrationsFrom(__DIR__ . '/../../database/migrations');

        if ($this->app->runningInConsole()) {
            $this->commands([
                CopyDefaultController::class,
            ]);
        }

        $this->extendAuthGuard();
    }

    protected function extendAuthGuard(): void
    {
        Auth::extend('jwt', function (Application $app, string $name, array $config) {
            return new JWTGuard(
                $app->make(JWTGenerator::class),
                $app->make(JWTValidator::class),
                $app->make(JWTParser::class),
                $app->make(Request::class),
                $app->make(TokenRefresher::class),
                Auth::createUserProvider($config['provider']),
                $app->make(TokenRequestGetter::class),
            );
        });
    }
}
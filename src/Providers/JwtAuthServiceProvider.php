<?php

namespace Kostyap\JwtAuth\Providers;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
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

        $this->extendAuthGuard();

        $this->copyDefaultImplementationFiles();
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
            );
        });
    }

    protected function copyDefaultImplementationFiles(): void
    {
        // Routes
        copy(__DIR__ . '/../../stubs/default/routes/auth.php', base_path('routes/auth.php'));

        // Controllers
        (new Filesystem)->ensureDirectoryExists(app_path('Http/Controllers'));
        (new Filesystem)->copyDirectory(
            __DIR__ . '/../../stubs/default/app/Http/Controllers',
            app_path('Http/Controllers')
        );

        // Requests
        (new Filesystem)->ensureDirectoryExists(app_path('Http/Requests'));
        (new Filesystem)->copyDirectory(
            __DIR__ . '/../../stubs/default/app/Http/Requests',
            app_path('Http/Requests')
        );
    }
}
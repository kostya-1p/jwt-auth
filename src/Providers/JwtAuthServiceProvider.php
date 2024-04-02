<?php

namespace Kostyap\JwtAuth\Providers;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Kostyap\JwtAuth\Helpers\TokenRequestGetter;
use Kostyap\JwtAuth\Jwt\Generation\JWTGenerator;
use Kostyap\JwtAuth\Jwt\Generation\JWTSigner;
use Kostyap\JwtAuth\Jwt\Generation\PayloadGenerator;
use Kostyap\JwtAuth\Jwt\Parsing\JWTParser;
use Kostyap\JwtAuth\Jwt\Validation\JWTValidator;
use Kostyap\JwtAuth\Jwt\Validation\PayloadValidator;
use Kostyap\JwtAuth\RefreshToken\Repository\DatabaseRefreshSessionRepository;
use Kostyap\JwtAuth\RefreshToken\Repository\RefreshSessionRepository;
use Kostyap\JwtAuth\RefreshToken\TokenRefresher;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Validator;

class JwtAuthServiceProvider extends ServiceProvider
{
    public const CONFIG_FILE_NAME = 'jwt';
    public const CONFIG_FULL_NAME = self::CONFIG_FILE_NAME . '.php';

    public array $bindings = [
        RefreshSessionRepository::class => DatabaseRefreshSessionRepository::class
    ];

    public function register(): void
    {
        $this->registerPayloadGenerator();
        $this->registerJwtSigner();
        $this->registerJwtParser();
        $this->registerPayloadValidator();
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../../config/config.php' => config_path(self::CONFIG_FULL_NAME)
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

    protected function registerPayloadGenerator(): void
    {
        $this->app->bind(PayloadGenerator::class, function (Application $app) {
            return new PayloadGenerator(
                $this->config('required_claims'),
                $this->config('ttl'),
                new Builder(new JoseEncoder(), ChainedFormatter::default())
            );
        });
    }

    protected function registerJwtSigner(): void
    {
        $this->app->bind(JWTSigner::class, function (Application $app) {
            return new JWTSigner(
                $this->config('algo'),
                $this->config('secret'),
                $this->config('keys.public'),
                $this->config('keys.private'),
            );
        });
    }

    protected function registerJwtParser(): void
    {
        $this->app->bind(JWTParser::class, function (Application $app) {
            return new JWTParser(new Parser(new JoseEncoder()));
        });
    }

    protected function registerPayloadValidator(): void
    {
        $this->app->bind(PayloadValidator::class, function (Application $app) {
            return new PayloadValidator(
                $this->config('required_claims'),
                new Validator(),
            );
        });
    }

    protected function config(string $key, $default = null): mixed
    {
        return config(self::CONFIG_FILE_NAME . '.' . $key, $default);
    }
}
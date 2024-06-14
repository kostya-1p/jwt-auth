<?php

namespace Kostyap\JwtAuth\Providers;

use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Kostyap\JwtAuth\Commands\CopyDefaultController;
use Kostyap\JwtAuth\Enums\AccessTokenSource;
use Kostyap\JwtAuth\Enums\RefreshTokenSource;
use Kostyap\JwtAuth\Enums\RefreshTokenStorage;
use Kostyap\JwtAuth\Exceptions\InvalidRepositoryImplementation;
use Kostyap\JwtAuth\Helpers\TokenRequestGetter;
use Kostyap\JwtAuth\Helpers\TokenResponseSetter;
use Kostyap\JwtAuth\JWTGuard;
use Kostyap\JwtAuth\JwtServices\Generators\JWTGenerator;
use Kostyap\JwtAuth\JwtServices\Generators\JWTSigner;
use Kostyap\JwtAuth\JwtServices\Generators\PayloadGenerator;
use Kostyap\JwtAuth\JwtServices\Parsers\JWTParser;
use Kostyap\JwtAuth\JwtServices\Validators\JWTValidator;
use Kostyap\JwtAuth\JwtServices\Validators\PayloadValidator;
use Kostyap\JwtAuth\JwtServices\Validators\SignatureValidator;
use Kostyap\JwtAuth\RefreshTokenServices\RefreshUtility;
use Kostyap\JwtAuth\RefreshTokenServices\Repositories\DatabaseRefreshSessionRepository;
use Kostyap\JwtAuth\RefreshTokenServices\Repositories\RefreshSessionRepositoryInterface;
use Kostyap\JwtAuth\RefreshTokenServices\TokenRefresher;
use Kostyap\JwtAuth\TokenHttpSources\Body;
use Kostyap\JwtAuth\TokenHttpSources\Cookie;
use Kostyap\JwtAuth\TokenHttpSources\HttpHandler;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Validator;

class JwtAuthServiceProvider extends ServiceProvider
{
    public const CONFIG_FILE_NAME = 'jwt';
    public const CONFIG_FULL_NAME = self::CONFIG_FILE_NAME . '.php';

    public function register(): void
    {
        $this->bindRefreshSessionRepository();
        $this->registerPayloadGenerator();
        $this->registerJwtSigner();
        $this->registerJwtParser();
        $this->registerPayloadValidator();
        $this->registerSignatureValidator();
        $this->registerRefreshUtility();
        $this->registerTokenRequestGetter();
        $this->registerTokenResponseSetter();
        $this->registerJwtValidator();
        $this->registerTokensHttpHandler();
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

    protected function bindRefreshSessionRepository(): void
    {
        $this->app->bind(RefreshSessionRepositoryInterface::class, function (Application $app) {
            /** @var RefreshTokenStorage $refreshTokenStorage */
            $refreshTokenStorage = $this->config('token_source.refresh_token_storage');
            return match ($refreshTokenStorage) {
                RefreshTokenStorage::Database => new DatabaseRefreshSessionRepository(),
                RefreshTokenStorage::Redis => throw new InvalidRepositoryImplementation(
                    'The Redis implementation is not yet complete'
                ),
            };
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

    protected function registerSignatureValidator(): void
    {
        $this->app->bind(SignatureValidator::class, function (Application $app) {
            return new SignatureValidator(
                $app->make(JWTSigner::class),
                new Validator(),
            );
        });
    }

    protected function registerRefreshUtility(): void
    {
        $this->app->bind(RefreshUtility::class, function (Application $app) {
            return new RefreshUtility(
                $app->make(RefreshSessionRepositoryInterface::class),
                $this->config('refresh_ttl', 20160),
            );
        });
    }

    protected function registerTokenRequestGetter(): void
    {
        $this->app->bind(TokenRequestGetter::class, function (Application $app) {
            return new TokenRequestGetter(
                $app->make(Request::class),
                $this->config('token_source.access_token'),
                $this->config('token_source.refresh_token'),
            );
        });
    }

    protected function registerTokenResponseSetter(): void
    {
        $this->app->bind(TokenResponseSetter::class, function (Application $app) {
            return new TokenResponseSetter(
                $this->config('token_source.access_token'),
                $this->config('token_source.refresh_token'),
                $this->config('refresh_ttl'),
            );
        });
    }

    protected function registerJwtValidator(): void
    {
        $this->app->bind(JWTValidator::class, function (Application $app) {
            return new JWTValidator(
                $app->make(PayloadValidator::class),
                $app->make(SignatureValidator::class),
                new Parser(new JoseEncoder()),
            );
        });
    }

    protected function registerTokensHttpHandler(): void
    {
        $this->app->bind(HttpHandler::class, function (Application $app) {
            $accessTokenSource = $this->config('token_source.access_token');
            $refreshTokenSource = $this->config('token_source.refresh_token');

            $accessTokenSource = match ($accessTokenSource) {
                AccessTokenSource::Bearer => new Body\BearerAccessTokenSource($app->make(Request::class)),
                AccessTokenSource::Cookie => new Cookie\AccessTokenSource(
                    $app->make(Request::class), $this->config('refresh_ttl')
                ),
                default => throw new BindingResolutionException(
                    'Cannot bind ' . HttpHandler::class . '. Incorrect access token source value: ' . $accessTokenSource
                )
            };

            $refreshTokenSource = match ($refreshTokenSource) {
                RefreshTokenSource::Body => new Body\BodyRefreshTokenSource($app->make(Request::class)),
                RefreshTokenSource::Cookie => new Cookie\RefreshTokenSource(
                    $app->make(Request::class), $this->config('refresh_ttl')
                ),
                default => throw new BindingResolutionException(
                    'Cannot bind ' . HttpHandler::class . '. Incorrect refresh token source value: ' . $refreshTokenSource
                )
            };

            return new HttpHandler($accessTokenSource, $refreshTokenSource);
        });
    }

    protected function config(string $key, mixed $default = null): mixed
    {
        return config(self::CONFIG_FILE_NAME . '.' . $key, $default);
    }
}
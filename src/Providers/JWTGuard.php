<?php

namespace Kostyap\JwtAuth\Providers;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Kostyap\JwtAuth\Helpers\TypeValidator;
use Kostyap\JwtAuth\Jwt\Data\TokenPair;
use Kostyap\JwtAuth\Jwt\Generation\JWTGenerator;
use Kostyap\JwtAuth\Jwt\JWTSubject;
use Kostyap\JwtAuth\Jwt\Parsing\JWTParser;
use Kostyap\JwtAuth\Jwt\Validation\JWTValidator;
use Kostyap\JwtAuth\RefreshToken\Data\RefreshMetaData;
use Kostyap\JwtAuth\RefreshToken\TokenRefresher;
use Throwable;

class JWTGuard implements Guard
{
    use GuardHelpers;

    public function __construct(
        private JWTGenerator $jwtGenerator,
        private JWTValidator $validator,
        private JWTParser $parser,
        private Request $request,
        private TokenRefresher $refresher,
        UserProvider $provider,
    ) {
        $this->provider = $provider;
    }

    /**
     * @inheritDoc
     */
    public function user(): JWTSubject|Authenticatable|null
    {
        if ($this->user !== null) {
            return $this->user;
        }

        /** @var string $token */
        $token = $this->request->input('access_token');

        try {
            $parsedToken = $this->parser->parse($token);
            $parsedToken = TypeValidator::checkUnencryptedTokenType($parsedToken);
            $userId = $this->parser->getClaim($parsedToken, 'sub');

            /** @var Authenticatable|JWTSubject|null $user */
            $user = $this->provider->retrieveById($userId);

            $this->validator->validateToken($token, $user);
            $this->user = $user;
        } catch (Throwable) {
            return null;
        }

        return $this->user;
    }

    /**
     * @inheritDoc
     */
    public function validate(array $credentials = []): bool
    {
        return (bool)$this->attempt($credentials, false);
    }

    public function attempt(array $credentials = [], bool $login = true): bool|TokenPair
    {
        /** @var Authenticatable|JWTSubject|null $user */
        $user = $this->provider->retrieveByCredentials($credentials);

        if ($this->hasValidCredentials($user, $credentials)) {
            return $login ? $this->login($user) : true;
        }

        return false;
    }

    //TODO: Доработать этот метод (что делать с исключениями, что делать если данные для refreshMetadata не все)
    public function login(JWTSubject $user): TokenPair
    {
        $accessToken = $this->jwtGenerator->fromSubject($user);

        $ip = $this->request->ip();
        $userAgent = $this->request->userAgent();
        $fingerPrint = $this->request->input('fingerprint');

        $refreshMetaData = RefreshMetaData::make($userAgent, $fingerPrint, $ip);

        $refreshToken = $this->refresher->generateToken($refreshMetaData);
        return TokenPair::make($accessToken, $refreshToken);
    }

    protected function hasValidCredentials(?Authenticatable $user, array $credentials): bool
    {
        return $user !== null && $this->provider->validateCredentials($user, $credentials);
    }
}
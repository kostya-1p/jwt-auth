<?php

namespace Kostyap\JwtAuth\Providers;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Kostyap\JwtAuth\Exceptions\InvalidClaimsException;
use Kostyap\JwtAuth\Exceptions\InvalidRefreshSession;
use Kostyap\JwtAuth\Exceptions\InvalidTokenException;
use Kostyap\JwtAuth\Exceptions\RequestInputException;
use Kostyap\JwtAuth\Exceptions\SignatureAlgorithmException;
use Kostyap\JwtAuth\Exceptions\SignatureKeyException;
use Kostyap\JwtAuth\Helpers\TypeValidator;
use Kostyap\JwtAuth\Jwt\Data\TokenPair;
use Kostyap\JwtAuth\Jwt\Generation\JWTGenerator;
use Kostyap\JwtAuth\Jwt\JWTSubject;
use Kostyap\JwtAuth\Jwt\Parsing\JWTParser;
use Kostyap\JwtAuth\Jwt\Validation\JWTValidator;
use Kostyap\JwtAuth\RefreshToken\Data\RefreshMetaData;
use Kostyap\JwtAuth\RefreshToken\TokenRefresher;
use Random\RandomException;
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
        $token = $this->request->bearerToken();

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

    /**
     * @throws SignatureAlgorithmException
     * @throws RandomException
     * @throws SignatureKeyException
     * @throws InvalidRefreshSession
     * @throws InvalidClaimsException
     */
    public function attempt(array $credentials = [], bool $login = true): bool|TokenPair
    {
        /** @var Authenticatable|JWTSubject|null $user */
        $user = $this->provider->retrieveByCredentials($credentials);

        if ($this->hasValidCredentials($user, $credentials)) {
            return $login ? $this->login($user) : true;
        }

        return false;
    }

    /**
     * @throws SignatureAlgorithmException
     * @throws RandomException
     * @throws SignatureKeyException
     * @throws InvalidRefreshSession
     * @throws InvalidClaimsException
     */
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

    public function refresh(): TokenPair
    {
        $tokenPair = $this->getTokenPair();
        $refreshMetaData = $this->getRefreshMetaData();

        $user = $this->getUserFromToken($tokenPair->accessToken);
        if (is_null($user)) {
            throw new InvalidTokenException('Could not get user from token');
        }

        return $this->refresher->refresh($tokenPair, $refreshMetaData, $user);
    }

    /**
     * @throws RequestInputException
     */
    private function getRefreshMetaData(): RefreshMetaData
    {
        $ip = $this->request->ip();
        $userAgent = $this->request->userAgent();
        $fingerPrint = $this->request->input('fingerprint');

        if (!$fingerPrint) {
            throw new RequestInputException('Fingerprint is required!');
        }
        return RefreshMetaData::make($userAgent, $fingerPrint, $ip);
    }

    /**
     * @throws InvalidTokenException
     */
    private function getTokenPair(): TokenPair
    {
        $accessToken = $this->request->bearerToken();
        $refreshToken = $this->request->cookie('refresh_token');

        if (is_null($accessToken) || is_null($refreshToken)) {
            throw new InvalidTokenException('Token is missing!');
        }

        return TokenPair::make($accessToken, $refreshToken);
    }

    private function getUserFromToken(string $token): Authenticatable|JWTSubject|null
    {
        $parsedToken = $this->parser->parse($token);
        $parsedToken = TypeValidator::checkUnencryptedTokenType($parsedToken);
        $userId = $this->parser->getClaim($parsedToken, 'sub');

        return $this->provider->retrieveById($userId);
    }
}
<?php

namespace Kostyap\JwtAuth\Providers;

use Exception;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Kostyap\JwtAuth\Enum\AccessTokenSource;
use Kostyap\JwtAuth\Enum\RefreshTokenSource;
use Kostyap\JwtAuth\Exceptions\InvalidClaimsException;
use Kostyap\JwtAuth\Exceptions\InvalidRefreshSession;
use Kostyap\JwtAuth\Exceptions\InvalidTokenException;
use Kostyap\JwtAuth\Exceptions\RequestInputException;
use Kostyap\JwtAuth\Exceptions\SignatureAlgorithmException;
use Kostyap\JwtAuth\Exceptions\SignatureKeyException;
use Kostyap\JwtAuth\Exceptions\TokenExpiredException;
use Kostyap\JwtAuth\Exceptions\TokenTypeException;
use Kostyap\JwtAuth\Helpers\TokenRequestGetter;
use Kostyap\JwtAuth\Helpers\TypeValidator;
use Kostyap\JwtAuth\Jwt\Data\TokenPair;
use Kostyap\JwtAuth\Jwt\Generation\JWTGenerator;
use Kostyap\JwtAuth\Jwt\JWTSubject;
use Kostyap\JwtAuth\Jwt\Parsing\JWTParser;
use Kostyap\JwtAuth\Jwt\Validation\JWTValidator;
use Kostyap\JwtAuth\RefreshToken\Data\RefreshMetaData;
use Kostyap\JwtAuth\RefreshToken\TokenRefresher;
use Lcobucci\JWT\Token\RegisteredClaims;
use Random\RandomException;

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
        private TokenRequestGetter $tokenRequestGetter,
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

        try {
            $token = $this->tokenRequestGetter->getAccessToken();
            $user = $this->getUserFromToken($token);
            if (is_null($user)) {
                throw new InvalidTokenException('Could not get user from token');
            }

            $this->validator->validateToken($token, $user);
            $this->user = $user;
        } catch (Exception) {
            return null;
        }

        return $this->user;
    }

    /**
     * @inheritDoc
     * @param array<string, string> $credentials
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
     * @throws RequestInputException
     *
     * @param array<string, string> $credentials
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
     * @throws RequestInputException
     */
    public function login(JWTSubject $user): TokenPair
    {
        $accessToken = $this->jwtGenerator->fromSubject($user);
        $refreshMetaData = $this->getRefreshMetaData();
        $refreshToken = $this->refresher->generateToken($refreshMetaData);
        return TokenPair::make($accessToken, $refreshToken);
    }

    /** @param array<string, string> $credentials */
    protected function hasValidCredentials(?Authenticatable $user, array $credentials): bool
    {
        return $user !== null && $this->provider->validateCredentials($user, $credentials);
    }

    /**
     * @throws SignatureAlgorithmException
     * @throws RandomException
     * @throws InvalidTokenException
     * @throws SignatureKeyException
     * @throws InvalidRefreshSession
     * @throws TokenExpiredException
     * @throws TokenTypeException
     * @throws RequestInputException
     * @throws InvalidClaimsException
     */
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
        $accessToken = $this->tokenRequestGetter->getAccessToken();
        $refreshToken = $this->tokenRequestGetter->getRefreshToken();

        return TokenPair::make($accessToken, $refreshToken);
    }

    /** @param non-empty-string $token */
    private function getUserFromToken(string $token): Authenticatable|JWTSubject|null
    {
        $parsedToken = $this->parser->parse($token);
        $parsedToken = TypeValidator::checkUnencryptedTokenType($parsedToken);
        $userId = $this->parser->getClaim($parsedToken, RegisteredClaims::SUBJECT);

        return $this->provider->retrieveById($userId);
    }
}
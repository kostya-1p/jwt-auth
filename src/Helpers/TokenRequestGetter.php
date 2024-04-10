<?php

namespace Kostyap\JwtAuth\Helpers;

use Illuminate\Http\Request;
use Kostyap\JwtAuth\Enum\AccessTokenSource;
use Kostyap\JwtAuth\Enum\RefreshTokenSource;
use Kostyap\JwtAuth\Exceptions\InvalidTokenException;

class TokenRequestGetter
{
    public const ACCESS_TOKEN_KEY = 'access_token';
    public const REFRESH_TOKEN_KEY = 'refresh_token';

    public function __construct(
        private Request $request,
        private AccessTokenSource $accessTokenSource,
        private RefreshTokenSource $refreshTokenSource,
    ) {
    }

    /**
     * @throws InvalidTokenException
     * @return non-empty-string
     */
    public function getAccessToken(): string
    {
        $accessToken = match ($this->accessTokenSource) {
            AccessTokenSource::Bearer => $this->request->bearerToken(),
            AccessTokenSource::Cookie => $this->request->cookie(self::ACCESS_TOKEN_KEY),
        };

        if (!$accessToken) {
            throw new InvalidTokenException('Token is missing!');
        }
        return $accessToken;
    }

    /**
     * @throws InvalidTokenException
     * @return non-empty-string
     */
    public function getRefreshToken(): string
    {
        $refreshToken = match ($this->refreshTokenSource) {
            RefreshTokenSource::Body => $this->request->input(self::REFRESH_TOKEN_KEY),
            RefreshTokenSource::Cookie => $this->request->cookie(self::REFRESH_TOKEN_KEY),
        };

        if (!$refreshToken) {
            throw new InvalidTokenException('Token is missing!');
        }
        return $refreshToken;
    }
}
<?php

namespace Kostyap\JwtAuth\Helpers;

use Illuminate\Http\Response;
use Kostyap\JwtAuth\Enum\AccessTokenSource;
use Kostyap\JwtAuth\Enum\RefreshTokenSource;
use Kostyap\JwtAuth\Jwt\Data\TokenPair;
use Symfony\Component\HttpFoundation\Cookie;

class TokenResponseSetter
{
    private AccessTokenSource $accessTokenSource;
    private RefreshTokenSource $refreshTokenSource;
    private int $ttl;
    private int $refreshTtl;

    public function __construct()
    {
        $this->accessTokenSource = config('jwt.token_source.access_token');
        $this->refreshTokenSource = config('jwt.token_source.refresh_token');
        $this->ttl = config('jwt.ttl');
        $this->refreshTtl = config('jwt.refresh_ttl');
    }

    public function setResponse(TokenPair $tokenPair): Response
    {
        $response = new Response();
        $responseContent = [];

        match ($this->accessTokenSource) {
            AccessTokenSource::Bearer => $responseContent['access_token'] = $tokenPair->accessToken,
            AccessTokenSource::Cookie => $response->withCookie(Cookie::create(
                'access_token',
                $tokenPair->accessToken,
                $this->ttl
            )),
        };

        match ($this->refreshTokenSource) {
            RefreshTokenSource::Body => $responseContent['refresh_token'] = $tokenPair->refreshToken,
            RefreshTokenSource::Cookie => $response->withCookie(Cookie::create(
                'refresh_token',
                $tokenPair->refreshToken,
                $this->refreshTtl
            )),
        };

        $response->setContent(empty($responseContent) ? 'Authenticated' : $responseContent);
        return $response;
    }
}
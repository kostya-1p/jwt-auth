<?php

namespace Kostyap\JwtAuth\Helpers;

use Carbon\Carbon;
use Illuminate\Http\Response;
use Kostyap\JwtAuth\Enum\AccessTokenSource;
use Kostyap\JwtAuth\Enum\RefreshTokenSource;
use Kostyap\JwtAuth\Jwt\Data\TokenPair;
use Symfony\Component\HttpFoundation\Cookie;

class TokenResponseSetter
{
    private AccessTokenSource $accessTokenSource;
    private RefreshTokenSource $refreshTokenSource;
    private int $refreshTtl;

    public function __construct()
    {
        $this->accessTokenSource = config('jwt.token_source.access_token');
        $this->refreshTokenSource = config('jwt.token_source.refresh_token');
        $this->refreshTtl = config('jwt.refresh_ttl');
    }

    public function setResponse(TokenPair $tokenPair, string $emptyBodyMessage = 'Authenticated'): Response
    {
        $response = new Response();
        $responseContent = [];

        match ($this->accessTokenSource) {
            AccessTokenSource::Bearer => $responseContent[TokenRequestGetter::ACCESS_TOKEN_KEY] = $tokenPair->accessToken,
            AccessTokenSource::Cookie => $response->withCookie(Cookie::create(
                TokenRequestGetter::ACCESS_TOKEN_KEY,
                $tokenPair->accessToken,
                Carbon::now()->addMinutes($this->refreshTtl),
            )),
        };

        match ($this->refreshTokenSource) {
            RefreshTokenSource::Body => $responseContent[TokenRequestGetter::REFRESH_TOKEN_KEY] = $tokenPair->refreshToken,
            RefreshTokenSource::Cookie => $response->withCookie(Cookie::create(
                TokenRequestGetter::REFRESH_TOKEN_KEY,
                $tokenPair->refreshToken,
                Carbon::now()->addMinutes($this->refreshTtl),
            )),
        };

        $response->setContent(empty($responseContent) ? $emptyBodyMessage : $responseContent);
        return $response;
    }
}
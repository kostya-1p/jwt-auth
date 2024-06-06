<?php

namespace Kostyap\JwtAuth\Helpers;

use Carbon\Carbon;
use Illuminate\Http\Response;
use Kostyap\JwtAuth\Enums\AccessTokenSource;
use Kostyap\JwtAuth\Enums\RefreshTokenSource;
use Kostyap\JwtAuth\JwtServices\Data\TokenPair;
use Symfony\Component\HttpFoundation\Cookie;

class TokenResponseSetter
{
    public function __construct(
        private AccessTokenSource $accessTokenSource,
        private RefreshTokenSource $refreshTokenSource,
        private int $refreshTtl,
    ) {
    }

    public function setResponse(TokenPair $tokenPair, string $emptyBodyMessage = 'Authenticated'): Response
    {
        $response = new Response();
        $responseContent = [];

        match ($this->accessTokenSource) {
            AccessTokenSource::Bearer => $responseContent[TokenRequestGetter::ACCESS_TOKEN_KEY] = $tokenPair->accessToken,
            AccessTokenSource::Cookie => $response->withCookie(
                Cookie::create(
                    TokenRequestGetter::ACCESS_TOKEN_KEY,
                    $tokenPair->accessToken,
                    Carbon::now()->addMinutes($this->refreshTtl),
                )
            ),
        };

        match ($this->refreshTokenSource) {
            RefreshTokenSource::Body => $responseContent[TokenRequestGetter::REFRESH_TOKEN_KEY] = $tokenPair->refreshToken,
            RefreshTokenSource::Cookie => $response->withCookie(
                Cookie::create(
                    TokenRequestGetter::REFRESH_TOKEN_KEY,
                    $tokenPair->refreshToken,
                    Carbon::now()->addMinutes($this->refreshTtl),
                )
            ),
        };

        $response->setContent(empty($responseContent) ? $emptyBodyMessage : $responseContent);
        return $response;
    }
}
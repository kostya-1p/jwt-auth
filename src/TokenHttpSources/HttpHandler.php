<?php

namespace Kostyap\JwtAuth\TokenHttpSources;

use Illuminate\Http\Response;
use Kostyap\JwtAuth\JwtServices\Data\TokenPair;

class HttpHandler
{
    public function __construct(
        private TokenSourceInterface $accessTokenSource,
        private TokenSourceInterface $refreshTokenSource,
    ) {
    }

    public function getTokens(): TokenPair
    {
        $accessToken = $this->accessTokenSource->getToken();
        $refreshToken = $this->refreshTokenSource->getToken();
        return new TokenPair($accessToken, $refreshToken);
    }

    public function setTokens(TokenPair $tokenPair, string $emptyBodyMessage = 'Authenticated'): Response
    {
        $response = new Response([]);
        $response = $this->accessTokenSource->setToken($response, $tokenPair->accessToken);
        $response = $this->refreshTokenSource->setToken($response, $tokenPair->refreshToken);

        $responseContent = $response->getOriginalContent();
        if (empty($responseContent)) {
            $response->setContent($emptyBodyMessage);
        }
        return $response;
    }
}
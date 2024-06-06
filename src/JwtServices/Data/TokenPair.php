<?php

namespace Kostyap\JwtAuth\JwtServices\Data;

class TokenPair
{
    /**
     * @param non-empty-string $accessToken
     * @param non-empty-string $refreshToken
     */
    public function __construct(public string $accessToken, public string $refreshToken)
    {
    }
}
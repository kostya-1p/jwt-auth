<?php

namespace Kostyap\JwtAuth\Jwt\Data;

class TokenPair
{
    /** @var non-empty-string */
    public string $accessToken;

    /** @var non-empty-string */
    public string $refreshToken;

    public static function make(string $accessToken, string $refreshToken): TokenPair
    {
        $dto = new self();
        $dto->accessToken = $accessToken;
        $dto->refreshToken = $refreshToken;
        return $dto;
    }
}
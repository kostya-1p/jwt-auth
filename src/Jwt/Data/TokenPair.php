<?php

namespace Kostyap\JwtAuth\Jwt\Data;

class TokenPair
{
    public string $accessToken;
    public string $refreshToken;

    public static function make(string $accessToken, string $refreshToken): TokenPair
    {
        $dto = new self();
        $dto->accessToken = $accessToken;
        $dto->refreshToken = $refreshToken;
        return $dto;
    }
}
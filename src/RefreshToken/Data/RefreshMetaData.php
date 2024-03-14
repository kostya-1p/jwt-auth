<?php

namespace Kostyap\JwtAuth\RefreshToken\Data;

class RefreshMetaData
{
    public string $userAgent;
    public string $fingerPrint;
    public string $ip;

    public static function make(string $userAgent, string $fingerPrint, string $ip): RefreshMetaData
    {
        $dto = new self();
        $dto->userAgent = $userAgent;
        $dto->fingerPrint = $fingerPrint;
        $dto->ip = $ip;
        return $dto;
    }
}
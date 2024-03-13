<?php

namespace Kostyap\JwtAuth\RefreshTokens;

use Carbon\Carbon;

class RefreshSessionData
{
    public int $id;
    public string $refreshToken;
    public string $userAgent;
    public string $fingerPrint;
    public string $ip;
    public Carbon $expiresIn;
    public Carbon $createdAt;

    public static function make(
        int $id,
        string $refreshToken,
        string $userAgent,
        string $fingerPrint,
        string $ip,
        Carbon $expiresIn,
        Carbon $createdAt
    ): RefreshSessionData {
        $dto = new self();
        $dto->id = $id;
        $dto->refreshToken = $refreshToken;
        $dto->userAgent = $userAgent;
        $dto->fingerPrint = $fingerPrint;
        $dto->ip = $ip;
        $dto->expiresIn = $expiresIn;
        $dto->createdAt = $createdAt;
        return $dto;
    }

    public static function fromStdClass(object $refreshSession): RefreshSessionData
    {
        $dto = new self();
        $dto->id = $refreshSession->id;
        $dto->refreshToken = $refreshSession->refresh_token;
        $dto->userAgent = $refreshSession->user_agent;
        $dto->fingerPrint = $refreshSession->fingerprint;
        $dto->ip = $refreshSession->ip;
        $dto->expiresIn = $refreshSession->expires_in;
        $dto->createdAt = $refreshSession->created_at;
        return $dto;
    }
}
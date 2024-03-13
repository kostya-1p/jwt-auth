<?php

namespace Kostyap\JwtAuth\RefreshToken\Data;

use Carbon\Carbon;

class RefreshSessionData
{
    public ?int $id;
    public string $refreshToken;
    public string $userAgent;
    public string $fingerPrint;
    public string $ip;
    public Carbon $expiresIn;
    public ?Carbon $createdAt;

    public static function make(
        ?int $id,
        string $refreshToken,
        string $userAgent,
        string $fingerPrint,
        string $ip,
        Carbon $expiresIn,
        ?Carbon $createdAt
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

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'refresh_token' => $this->refreshToken,
            'user_agent' => $this->userAgent,
            'fingerprint' => $this->fingerPrint,
            'ip' => $this->ip,
            'expires_in' => $this->expiresIn,
            'created_at' => $this->createdAt,
        ];
    }
}
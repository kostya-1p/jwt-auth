<?php

namespace Kostyap\JwtAuth\RefreshTokenServices\Data;

use Carbon\Carbon;

class RefreshSessionData
{
    public function __construct(
        public ?int $id,
        public string $refreshToken,
        public string $userAgent,
        public string $fingerPrint,
        public string $ip,
        public Carbon $expiresIn,
        public ?Carbon $createdAt,
    ) {
    }

    public static function fromStdClass(object $refreshSession): self
    {
        return new self(
            $refreshSession->id,
            $refreshSession->refresh_token,
            $refreshSession->user_agent,
            $refreshSession->fingerprint,
            $refreshSession->ip,
            $refreshSession->expires_in,
            $refreshSession->created_at,
        );
    }

    /** @return array<string, mixed> */
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
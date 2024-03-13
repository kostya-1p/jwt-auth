<?php

namespace Kostyap\JwtAuth\RefreshTokens\Repository;

use Kostyap\JwtAuth\RefreshTokens\RefreshSessionData;

interface RefreshSessionRepository
{
    public function getByRefreshToken(string $refreshToken): RefreshSessionData;

    public function store(RefreshSessionData $refreshSession): RefreshSessionData;

    public function delete(RefreshSessionData $refreshSession): bool;
}
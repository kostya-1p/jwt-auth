<?php

namespace Kostyap\JwtAuth\RefreshToken\Repository;

use Kostyap\JwtAuth\RefreshToken\Data\RefreshSessionData;

interface RefreshSessionRepository
{
    public function getByRefreshToken(string $refreshToken): ?RefreshSessionData;

    public function store(RefreshSessionData $refreshSession): bool;

    public function delete(RefreshSessionData $refreshSession): bool;
}
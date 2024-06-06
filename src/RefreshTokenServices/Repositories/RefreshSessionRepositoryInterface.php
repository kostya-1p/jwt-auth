<?php

namespace Kostyap\JwtAuth\RefreshTokenServices\Repositories;

use Kostyap\JwtAuth\RefreshTokenServices\Data\RefreshSessionData;

interface RefreshSessionRepositoryInterface
{
    public function getByRefreshToken(string $refreshToken): ?RefreshSessionData;

    public function store(RefreshSessionData $refreshSession): bool;

    public function delete(RefreshSessionData $refreshSession): bool;
}
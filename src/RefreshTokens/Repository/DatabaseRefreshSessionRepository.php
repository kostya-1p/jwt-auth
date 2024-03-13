<?php

namespace Kostyap\JwtAuth\RefreshTokens\Repository;

use Illuminate\Support\Facades\DB;
use Kostyap\JwtAuth\RefreshTokens\RefreshSessionData;

class DatabaseRefreshSessionRepository implements RefreshSessionRepository
{
    private const TABLE_NAME = 'refresh_sessions';

    public function getByRefreshToken(string $refreshToken): RefreshSessionData
    {
        $refreshSession = DB::table(self::TABLE_NAME)
            ->where('refresh_token', $refreshToken)
            ->first();


    }

    public function store(RefreshSessionData $refreshSession): RefreshSessionData
    {
        // TODO: Implement store() method.
    }

    public function delete(RefreshSessionData $refreshSession): bool
    {
        // TODO: Implement delete() method.
    }
}
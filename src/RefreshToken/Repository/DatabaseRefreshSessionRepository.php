<?php

namespace Kostyap\JwtAuth\RefreshToken\Repository;

use Carbon\Carbon;
use Illuminate\Support\Facades\DB;
use Kostyap\JwtAuth\Jwt\Generation\PayloadGenerator;
use Kostyap\JwtAuth\RefreshToken\Data\RefreshSessionData;

class DatabaseRefreshSessionRepository implements RefreshSessionRepository
{
    private const TABLE_NAME = 'refresh_sessions';

    public function getByRefreshToken(string $refreshToken): RefreshSessionData
    {
        $refreshSession = DB::table(self::TABLE_NAME)
            ->where('refresh_token', $refreshToken)
            ->first();

        $refreshSession->expires_in = Carbon::parse($refreshSession->expires_in, PayloadGenerator::CARBON_TIMEZONE);
        $refreshSession->created_at = Carbon::parse($refreshSession->created_at, PayloadGenerator::CARBON_TIMEZONE);

        return RefreshSessionData::fromStdClass($refreshSession);
    }

    public function store(RefreshSessionData $refreshSession): bool
    {
        $refreshSessionArray = $refreshSession->toArray();
        $refreshSessionArray['expires_in'] = $refreshSession->expiresIn->unix();
        $refreshSessionArray = array_filter($refreshSessionArray);

        return DB::table(self::TABLE_NAME)->insert($refreshSessionArray);
    }

    public function delete(RefreshSessionData $refreshSession): bool
    {
        return (bool)DB::table(self::TABLE_NAME)->delete($refreshSession->id);
    }
}
<?php

namespace Kostyap\JwtAuth\RefreshTokens\Repository;

use Carbon\Carbon;
use Illuminate\Support\Facades\DB;
use Kostyap\JwtAuth\Jwt\Generation\PayloadGenerator;
use Kostyap\JwtAuth\RefreshTokens\RefreshSessionData;

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

    public function store(RefreshSessionData $refreshSession): RefreshSessionData
    {
        $session = $refreshSession->toArray();
        $session['expires_in'] = $refreshSession->expiresIn->unix();

        DB::table(self::TABLE_NAME)
            ->insert($session);


    }

    public function delete(RefreshSessionData $refreshSession): bool
    {
        return (bool)DB::table(self::TABLE_NAME)->delete($refreshSession->id);
    }
}
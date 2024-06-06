<?php

namespace Kostyap\JwtAuth\RefreshTokenServices;

use Carbon\Carbon;
use Kostyap\JwtAuth\Exceptions\InvalidRefreshSession;
use Kostyap\JwtAuth\Exceptions\TokenExpiredException;
use Kostyap\JwtAuth\JwtServices\Generators\PayloadGenerator;
use Kostyap\JwtAuth\RefreshTokenServices\Data\RefreshMetaData;
use Kostyap\JwtAuth\RefreshTokenServices\Data\RefreshSessionData;
use Kostyap\JwtAuth\RefreshTokenServices\Repositories\RefreshSessionRepositoryInterface;
use Random\RandomException;

class RefreshUtility
{
    private const TOKEN_LENGTH = 16;

    public function __construct(
        private RefreshSessionRepositoryInterface $refreshSessionRepository,
        private int $refreshTtl
    ) {
    }

    /**
     * @throws TokenExpiredException
     * @throws InvalidRefreshSession
     */
    public function validateToken(RefreshMetaData $refreshMetaData, string $refreshToken): RefreshSessionData
    {
        $refreshSession = $this->refreshSessionRepository->getByRefreshToken($refreshToken);
        if (is_null($refreshSession)) {
            throw new InvalidRefreshSession('Refresh token is invalid');
        }

        $currentTime = Carbon::now(PayloadGenerator::CARBON_TIMEZONE);
        if ($currentTime->gte($refreshSession->expiresIn)) {
            $this->invalidateRefreshSession($refreshSession);
            throw new TokenExpiredException('Refresh token expired');
        }

        if ($refreshMetaData->fingerPrint !== $refreshSession->fingerPrint) {
            throw new InvalidRefreshSession('Invalid fingerprint');
        }

        return $refreshSession;
    }

    /**
     * @throws InvalidRefreshSession
     * @throws RandomException
     */
    public function generateToken(RefreshMetaData $refreshMetaData): RefreshSessionData
    {
        $refreshToken = bin2hex(random_bytes(self::TOKEN_LENGTH));

        $tokenCreatedAt = Carbon::now(PayloadGenerator::CARBON_TIMEZONE);
        $tokenExpiresIn = (clone $tokenCreatedAt)->addMinutes($this->refreshTtl);

        $refreshSession = RefreshSessionData::make(
            null,
            $refreshToken,
            $refreshMetaData->userAgent,
            $refreshMetaData->fingerPrint,
            $refreshMetaData->ip,
            $tokenExpiresIn,
            $tokenCreatedAt
        );

        $isStored = $this->refreshSessionRepository->store($refreshSession);
        if (!$isStored) {
            throw new InvalidRefreshSession('Unsuccessful refresh token generation');
        }

        return $refreshSession;
    }

    /**
     * @throws InvalidRefreshSession
     */
    public function invalidateRefreshSession(RefreshSessionData $refreshSession): void
    {
        $isDeleted = $this->refreshSessionRepository->delete($refreshSession);
        if (!$isDeleted) {
            throw new InvalidRefreshSession('Unsuccessful refresh token invalidation');
        }
    }
}
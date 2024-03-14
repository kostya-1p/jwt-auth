<?php

namespace Kostyap\JwtAuth\RefreshToken;

use Kostyap\JwtAuth\Exceptions\InvalidClaimsException;
use Kostyap\JwtAuth\Exceptions\InvalidRefreshSession;
use Kostyap\JwtAuth\Exceptions\TokenExpiredException;
use Kostyap\JwtAuth\Jwt\Data\TokenPair;
use Kostyap\JwtAuth\Jwt\Generation\JWTGenerator;
use Kostyap\JwtAuth\Jwt\JWTSubject;
use Kostyap\JwtAuth\Jwt\Validation\JWTValidator;
use Kostyap\JwtAuth\RefreshToken\Data\RefreshMetaData;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;

class TokenRefresher
{
    public function __construct(
        private JWTValidator $jwtValidator,
        private JWTGenerator $jwtGenerator,
        private JWTSubject $subject,
        private RefreshUtility $refreshUtility,
    ) {
    }

    /**
     * @throws TokenExpiredException
     * @throws InvalidRefreshSession
     * @throws InvalidClaimsException
     * @throws RequiredConstraintsViolated
     */
    public function refresh(string $accessToken, string $refreshToken, RefreshMetaData $refreshMetaData): TokenPair
    {
        $this->jwtValidator->validateToken($accessToken, $this->subject);

        $refreshSession = $this->refreshUtility->checkToken($refreshMetaData, $refreshToken);
        $this->refreshUtility->invalidateRefreshSession($refreshSession);
        $newRefreshSession = $this->refreshUtility->generateToken($refreshMetaData);

        $newAccessToken = $this->jwtGenerator->fromSubject($this->subject);
        $newRefreshToken = $newRefreshSession->refreshToken;

        return TokenPair::make($newAccessToken, $newRefreshToken);
    }
}
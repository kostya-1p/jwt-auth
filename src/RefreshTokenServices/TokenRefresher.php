<?php

namespace Kostyap\JwtAuth\RefreshTokenServices;

use Kostyap\JwtAuth\Exceptions\InvalidClaimsException;
use Kostyap\JwtAuth\Exceptions\InvalidRefreshSession;
use Kostyap\JwtAuth\Exceptions\SignatureAlgorithmException;
use Kostyap\JwtAuth\Exceptions\SignatureKeyException;
use Kostyap\JwtAuth\Exceptions\TokenExpiredException;
use Kostyap\JwtAuth\Exceptions\TokenTypeException;
use Kostyap\JwtAuth\JwtServices\Data\TokenPair;
use Kostyap\JwtAuth\JwtServices\Generators\JWTGenerator;
use Kostyap\JwtAuth\JwtServices\JWTSubject;
use Kostyap\JwtAuth\JwtServices\Validators\JWTValidator;
use Kostyap\JwtAuth\RefreshTokenServices\Data\RefreshMetaData;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Random\RandomException;

class TokenRefresher
{
    public function __construct(
        private JWTValidator $jwtValidator,
        private JWTGenerator $jwtGenerator,
        private RefreshUtility $refreshUtility,
    ) {
    }

    /**
     * @throws TokenExpiredException
     * @throws InvalidRefreshSession
     * @throws InvalidClaimsException
     * @throws RequiredConstraintsViolated
     * @throws RandomException
     * @throws TokenTypeException
     * @throws SignatureAlgorithmException
     * @throws SignatureKeyException
     */
    public function refresh(TokenPair $tokenPair, RefreshMetaData $refreshMetaData, JWTSubject $subject): TokenPair
    {
        $this->jwtValidator->validateExcludingTime($tokenPair->accessToken, $subject);

        $refreshSession = $this->refreshUtility->validateToken($refreshMetaData, $tokenPair->refreshToken);
        $this->refreshUtility->invalidateRefreshSession($refreshSession);
        $newRefreshSession = $this->refreshUtility->generateToken($refreshMetaData);

        $newAccessToken = $this->jwtGenerator->fromSubject($subject);
        $newRefreshToken = $newRefreshSession->refreshToken;

        return TokenPair::make($newAccessToken, $newRefreshToken);
    }

    /**
     * @throws InvalidRefreshSession
     * @throws RandomException
     */
    public function generateToken(RefreshMetaData $refreshMetaData): string
    {
        return $this->refreshUtility->generateToken($refreshMetaData)->refreshToken;
    }
}
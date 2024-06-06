<?php

namespace Kostyap\JwtAuth\JwtServices\Generators;

use Kostyap\JwtAuth\Exceptions\InvalidClaimsException;
use Kostyap\JwtAuth\Exceptions\SignatureAlgorithmException;
use Kostyap\JwtAuth\Exceptions\SignatureKeyException;
use Kostyap\JwtAuth\JwtServices\JWTSubject;

class JWTGenerator
{
    public function __construct(
        private JWTSigner $signer,
        private PayloadGenerator $payloadGenerator,
    ) {
    }

    /**
     * @throws SignatureAlgorithmException
     * @throws SignatureKeyException
     * @throws InvalidClaimsException
     */
    public function fromSubject(JWTSubject $subject): string
    {
        $algorithm = $this->signer->getJWTSigner();
        $signingKey = $this->signer->getSigningKey();
        $token = $this->payloadGenerator->getBuilderWithClaims($subject);

        $token = $token->getToken($algorithm, $signingKey);
        return $token->toString();
    }
}
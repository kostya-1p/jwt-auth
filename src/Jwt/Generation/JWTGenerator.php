<?php

namespace Kostyap\JwtAuth\Jwt\Generation;

use Kostyap\JwtAuth\Jwt\JWTSubject;

class JWTGenerator
{
    public function __construct(
        private JWTSigner $signer,
        private PayloadGenerator $payloadGenerator,
    ) {
    }

    public function fromSubject(JWTSubject $subject): string
    {
        $algorithm = $this->signer->getJWTSigner();
        $signingKey = $this->signer->getSigningKey();
        $token = $this->payloadGenerator->getBuilderWithClaims($subject);

        $token = $token->getToken($algorithm, $signingKey);
        return $token->toString();
    }
}
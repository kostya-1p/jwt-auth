<?php

namespace Kostyap\JwtAuth;

class JWT
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
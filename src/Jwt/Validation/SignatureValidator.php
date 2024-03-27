<?php

namespace Kostyap\JwtAuth\Jwt\Validation;

use Kostyap\JwtAuth\Exceptions\JWTException;
use Kostyap\JwtAuth\Jwt\Generation\JWTSigner;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validation\Validator;

class SignatureValidator
{
    public function __construct(
        private JWTSigner $signer
    ) {
    }

    /**
     * @throws RequiredConstraintsViolated
     * @throws JWTException
     */
    public function validateSignature(Token $token): void
    {
        $algorithm = $this->signer->getJWTSigner();
        $verificationKey = $this->signer->getVerificationKey();

        //TODO: don't create new validator instance here
        $validator = new Validator();
        $validator->assert($token, new SignedWith($algorithm, $verificationKey));
    }
}
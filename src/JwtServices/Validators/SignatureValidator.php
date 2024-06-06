<?php

namespace Kostyap\JwtAuth\JwtServices\Validators;

use Kostyap\JwtAuth\Exceptions\SignatureAlgorithmException;
use Kostyap\JwtAuth\Exceptions\SignatureKeyException;
use Kostyap\JwtAuth\JwtServices\Generators\JWTSigner;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validation\Validator;

class SignatureValidator
{
    public function __construct(
        private JWTSigner $signer,
        private Validator $validator,
    ) {
    }

    /**
     * @throws RequiredConstraintsViolated
     * @throws SignatureAlgorithmException
     * @throws SignatureKeyException
     */
    public function validateSignature(Token $token): void
    {
        $algorithm = $this->signer->getJWTSigner();
        $verificationKey = $this->signer->getVerificationKey();

        $this->validator->assert($token, new SignedWith($algorithm, $verificationKey));
    }
}
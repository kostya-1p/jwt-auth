<?php

namespace Kostyap\JwtAuth\Jwt\Validation;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validation\Validator;

class SignatureValidator
{
    public function __construct(
        private readonly Signer $signer,
        private readonly Key $key
    ) {
    }

    /** @throws RequiredConstraintsViolated */
    public function checkSignature(Token $token): void
    {
        //TODO: don't create new validator instance here
        $validator = new Validator();
        $validator->assert($token, new SignedWith($this->signer, $this->key));
    }
}
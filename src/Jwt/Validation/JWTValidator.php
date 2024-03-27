<?php

namespace Kostyap\JwtAuth\Jwt\Validation;

use Kostyap\JwtAuth\Exceptions\InvalidClaimsException;
use Kostyap\JwtAuth\Exceptions\SignatureAlgorithmException;
use Kostyap\JwtAuth\Exceptions\SignatureKeyException;
use Kostyap\JwtAuth\Exceptions\TokenTypeException;
use Kostyap\JwtAuth\Helpers\TypeValidator;
use Kostyap\JwtAuth\Jwt\JWTSubject;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;

class JWTValidator
{
    public function __construct(
        private PayloadValidator $payloadValidator,
        private SignatureValidator $signatureValidator,
    ) {
    }

    /**
     * @throws InvalidClaimsException
     * @throws RequiredConstraintsViolated
     * @throws TokenTypeException
     * @throws SignatureAlgorithmException
     * @throws SignatureKeyException
     */
    public function validateToken(string $token, JWTSubject $subject): void
    {
        //TODO: Don't create parser here
        $parser = new Parser(new JoseEncoder());

        $token = $parser->parse($token);

        $token = TypeValidator::checkUnencryptedTokenType($token);
        $this->payloadValidator->validatePayload($token, $subject);
        $this->signatureValidator->validateSignature($token);
    }
}
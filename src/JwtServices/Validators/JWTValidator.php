<?php

namespace Kostyap\JwtAuth\JwtServices\Validators;

use Kostyap\JwtAuth\Exceptions\InvalidClaimsException;
use Kostyap\JwtAuth\Exceptions\SignatureAlgorithmException;
use Kostyap\JwtAuth\Exceptions\SignatureKeyException;
use Kostyap\JwtAuth\Exceptions\TokenTypeException;
use Kostyap\JwtAuth\Helpers\TypeValidator;
use Kostyap\JwtAuth\JwtServices\JWTSubject;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;

class JWTValidator
{
    public function __construct(
        private PayloadValidator $payloadValidator,
        private SignatureValidator $signatureValidator,
        private Parser $parser,
    ) {
    }

    /**
     * @throws InvalidClaimsException
     * @throws RequiredConstraintsViolated
     * @throws TokenTypeException
     * @throws SignatureAlgorithmException
     * @throws SignatureKeyException
     * @param non-empty-string $token
     */
    public function validateToken(string $token, JWTSubject $subject): void
    {
        $token = $this->parser->parse($token);

        $token = TypeValidator::checkUnencryptedTokenType($token);
        $this->payloadValidator->validatePayload($token, $subject);
        $this->signatureValidator->validateSignature($token);
    }

    /**
     * @throws SignatureAlgorithmException
     * @throws TokenTypeException
     * @throws SignatureKeyException
     * @throws InvalidClaimsException
     * @throws RequiredConstraintsViolated
     * @param non-empty-string $token
     */
    public function validateExcludingTime(string $token, JWTSubject $subject): void
    {
        $token = $this->parser->parse($token);

        $token = TypeValidator::checkUnencryptedTokenType($token);
        $this->payloadValidator->validateExcludingTime($token, $subject);
        $this->signatureValidator->validateSignature($token);
    }
}
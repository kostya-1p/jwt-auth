<?php

namespace Kostyap\JwtAuth\Jwt\Validation;

use DateTimeZone;
use Kostyap\JwtAuth\Exceptions\InvalidClaimsException;
use Kostyap\JwtAuth\Jwt\Generation\PayloadGenerator;
use Kostyap\JwtAuth\Jwt\JWTSubject;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\RelatedTo;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\Validator;

class PayloadValidator
{
    private array $requiredClaims;

    public function __construct()
    {
        $this->requiredClaims = config('jwt.required_claims');
    }

    public function validatePayload(Token $token, JWTSubject $subject): void
    {
        //TODO: don't create new validator instance here
        $validator = new Validator();

        //TODO: Is it right to pass psr/clock this way?
        $validator->assert($token, new StrictValidAt(new SystemClock(
            new DateTimeZone(PayloadGenerator::CARBON_TIMEZONE)
        )));

        foreach ($this->requiredClaims as $claim) {
            match ($claim) {
                RegisteredClaims::ID => $validator->assert($token, new IdentifiedBy()),
                RegisteredClaims::ISSUER => $validator->assert($token, new IssuedBy()),
                RegisteredClaims::SUBJECT => $validator->assert($token, new RelatedTo($subject->getJWTIdentifier())),
                default => throw new InvalidClaimsException('Unexpected JWT default claim'),
            };
        }
    }
}
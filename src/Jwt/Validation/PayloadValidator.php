<?php

namespace Kostyap\JwtAuth\Jwt\Validation;

use DateTimeZone;
use Kostyap\JwtAuth\Exceptions\InvalidClaimsException;
use Kostyap\JwtAuth\Jwt\Generation\PayloadGenerator;
use Kostyap\JwtAuth\Jwt\JWTSubject;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\RelatedTo;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validation\Validator;

class PayloadValidator
{
    private array $requiredClaims;

    public function __construct()
    {
        $this->requiredClaims = config('jwt.required_claims');
    }

    /**
     * @throws InvalidClaimsException
     * @throws RequiredConstraintsViolated
     */
    public function validatePayload(UnencryptedToken $token, JWTSubject $subject): void
    {
        //TODO: don't create new validator instance here
        $validator = new Validator();

        $this->validateTokenTime($validator, $token);
        $this->validateDefaultClaims($validator, $token, $subject);
        $this->validateCustomClaims($token, $subject);
    }

    /**
     * @throws RequiredConstraintsViolated
     */
    private function validateTokenTime(Validator $validator, UnencryptedToken $token): void
    {
        //TODO: Is it right to pass psr/clock this way?
        $validator->assert($token, new StrictValidAt(new SystemClock(
            new DateTimeZone(PayloadGenerator::CARBON_TIMEZONE)
        )));
    }

    /**
     * @throws InvalidClaimsException
     * @throws RequiredConstraintsViolated
     */
    private function validateDefaultClaims(Validator $validator, UnencryptedToken $token, JWTSubject $subject): void
    {
        $tokenClaims = $token->claims();

        /** @var string $claim */
        foreach ($this->requiredClaims as $claim) {
            if (!$tokenClaims->has($claim)) {
                throw new InvalidClaimsException('Token payload does not contain required claim: ' . $claim);
            }

            match ($claim) {
                RegisteredClaims::AUDIENCE => $validator->assert($token, new PermittedFor($this->getCurrentHost())),
                RegisteredClaims::SUBJECT => $validator->assert($token, new RelatedTo($subject->getJWTIdentifier())),
                RegisteredClaims::ISSUER, RegisteredClaims::ISSUED_AT, RegisteredClaims::EXPIRATION_TIME,
                RegisteredClaims::NOT_BEFORE, RegisteredClaims::ID => null,
                default => throw new InvalidClaimsException('Unexpected JWT default claim'),
            };
        }
    }

    /**
     * @throws InvalidClaimsException
     */
    private function validateCustomClaims(UnencryptedToken $token, JWTSubject $subject): void
    {
        $tokenClaims = $token->claims();
        $customClaims = $subject->getJWTCustomClaims();

        foreach ($customClaims as $key => $claim) {
            if (!$tokenClaims->has($key)) {
                throw new InvalidClaimsException('Token payload does not contain custom claim ' . $claim . ' with key ' . $key);
            }
        }
    }

    private function getCurrentHost(): string
    {
        return (empty($_SERVER['HTTPS']) ? 'http' : 'https') . "://$_SERVER[HTTP_HOST]";
    }
}
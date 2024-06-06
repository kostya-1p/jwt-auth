<?php

namespace Kostyap\JwtAuth\JwtServices\Validators;

use DateTimeZone;
use Kostyap\JwtAuth\Exceptions\InvalidClaimsException;
use Kostyap\JwtAuth\JwtServices\Generators\PayloadGenerator;
use Kostyap\JwtAuth\JwtServices\JWTSubject;
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
    /** @param string[] $requiredClaims */
    public function __construct(private array $requiredClaims, private Validator $validator)
    {
    }

    /**
     * @throws InvalidClaimsException
     * @throws RequiredConstraintsViolated
     */
    public function validatePayload(UnencryptedToken $token, JWTSubject $subject): void
    {
        $this->validateTokenTime($token);
        $this->validateDefaultClaims($token, $subject);
        $this->validateCustomClaims($token, $subject);
    }

    /**
     * @throws InvalidClaimsException
     * @throws RequiredConstraintsViolated
     */
    public function validateExcludingTime(UnencryptedToken $token, JWTSubject $subject): void
    {
        $this->validateDefaultClaims($token, $subject);
        $this->validateCustomClaims($token, $subject);
    }

    /**
     * @throws RequiredConstraintsViolated
     */
    private function validateTokenTime(UnencryptedToken $token): void
    {
        $this->validator->assert($token, new StrictValidAt(new SystemClock(
            new DateTimeZone(PayloadGenerator::CARBON_TIMEZONE)
        )));
    }

    /**
     * @throws InvalidClaimsException
     * @throws RequiredConstraintsViolated
     */
    private function validateDefaultClaims(UnencryptedToken $token, JWTSubject $subject): void
    {
        $tokenClaims = $token->claims();

        foreach ($this->requiredClaims as $claim) {
            if (!$tokenClaims->has($claim)) {
                throw new InvalidClaimsException('Token payload does not contain required claim: ' . $claim);
            }

            match ($claim) {
                RegisteredClaims::AUDIENCE => $this->validator->assert($token, new PermittedFor($this->getCurrentHost())),
                RegisteredClaims::SUBJECT => $this->validator->assert($token, new RelatedTo($subject->getJWTIdentifier())),
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

    /** @return non-empty-string */
    private function getCurrentHost(): string
    {
        return (empty($_SERVER['HTTPS']) ? 'http' : 'https') . "://$_SERVER[HTTP_HOST]";
    }
}
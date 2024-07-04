<?php

namespace Kostyap\JwtAuth\JwtServices\Generators;

use Carbon\Carbon;
use DateTimeImmutable;
use Kostyap\JwtAuth\Exceptions\InvalidClaimsException;
use Kostyap\JwtAuth\Helpers\RequestUrlHelper;
use Kostyap\JwtAuth\JwtServices\JWTSubject;
use Lcobucci\JWT\Builder as BuilderInterface;
use Lcobucci\JWT\Token\RegisteredClaims;

class PayloadGenerator
{
    public const CARBON_TIMEZONE = 'UTC';
    private const JTI_LENGTH = 16;

    /** @param string[] $claims */
    public function __construct(
        private array $claims,
        private int $ttl,
        private BuilderInterface $tokenBuilder
    ) {
    }

    /**
     * @throws InvalidClaimsException
     */
    public function getBuilderWithClaims(JWTSubject $subject): BuilderInterface
    {
        foreach ($this->claims as $claim) {
            $this->tokenBuilder = match ($claim) {
                RegisteredClaims::ISSUED_AT => $this->tokenBuilder->issuedAt($this->iat()),

                RegisteredClaims::EXPIRATION_TIME => $this->tokenBuilder->expiresAt($this->exp()),

                RegisteredClaims::NOT_BEFORE => $this->tokenBuilder->canOnlyBeUsedAfter($this->nbf()),

                RegisteredClaims::ID => $this->tokenBuilder->identifiedBy($this->jti()),

                RegisteredClaims::ISSUER => $this->tokenBuilder->issuedBy($this->iss()),

                RegisteredClaims::AUDIENCE => $this->tokenBuilder->permittedFor($this->aud()),

                RegisteredClaims::SUBJECT => $this->tokenBuilder->relatedTo($subject->getJWTIdentifier()),

                default => throw new InvalidClaimsException('Unexpected JWT default claim'),
            };
        }

        $customClaims = $subject->getJWTCustomClaims();

        foreach ($customClaims as $key => $value) {
            $this->tokenBuilder = $this->tokenBuilder->withClaim($key, $value);
        }

        return $this->tokenBuilder;
    }

    /** @return non-empty-string */
    private function iss(): string
    {
        return RequestUrlHelper::getCurrentUrl();
    }

    private function iat(): DateTimeImmutable
    {
        return Carbon::now(self::CARBON_TIMEZONE)->toDateTimeImmutable();
    }

    private function exp(): DateTimeImmutable
    {
        return Carbon::now(self::CARBON_TIMEZONE)->addMinutes($this->ttl)->toDateTimeImmutable();
    }

    private function nbf(): DateTimeImmutable
    {
        return Carbon::now(self::CARBON_TIMEZONE)->toDateTimeImmutable();
    }

    /** @return non-empty-string */
    private function jti(): string
    {
        return base64_encode(random_bytes(self::JTI_LENGTH));
    }

    /** @return non-empty-string */
    private function aud(): string
    {
        return RequestUrlHelper::getCurrentHost();
    }
}
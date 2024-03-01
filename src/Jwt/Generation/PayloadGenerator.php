<?php

namespace Kostyap\JwtAuth\Jwt\Generation;

use Carbon\Carbon;
use DateTimeImmutable;
use Kostyap\JwtAuth\Exceptions\InvalidClaimsException;
use Kostyap\JwtAuth\Jwt\JWTSubject;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\RegisteredClaims;

class PayloadGenerator
{
    public const CARBON_TIMEZONE = 'UTC';

    private array $claims;
    private int $ttl;

    public function __construct()
    {
        $this->claims = config('jwt.required_claims');
        $this->ttl = config('jwt.ttl');
    }

    /**
     * @throws InvalidClaimsException
     */
    public function getBuilderWithClaims(JWTSubject $subject): Builder
    {
        //TODO: don't create new Builder here
        $tokenBuilder = (new Builder(new JoseEncoder(), ChainedFormatter::default()));

        foreach ($this->claims as $claim) {
            match ($claim) {
                RegisteredClaims::ISSUED_AT => $tokenBuilder->issuedAt($this->iat()),

                RegisteredClaims::EXPIRATION_TIME => $tokenBuilder->expiresAt($this->exp()),

                RegisteredClaims::NOT_BEFORE => $tokenBuilder->canOnlyBeUsedAfter($this->nbf()),

                RegisteredClaims::ID => $tokenBuilder->identifiedBy($this->jti()),

                RegisteredClaims::ISSUER => $tokenBuilder->issuedBy($this->iss()),

                RegisteredClaims::AUDIENCE => $tokenBuilder->permittedFor($this->aud()),

                RegisteredClaims::SUBJECT => $tokenBuilder->relatedTo($subject->getJWTIdentifier()),

                default => throw new InvalidClaimsException('Unexpected JWT default claim'),
            };
        }

        $customClaims = $subject->getJWTCustomClaims();

        foreach ($customClaims as $key => $value) {
            $tokenBuilder->withClaim($key, $value);
        }

        return $tokenBuilder;
    }

    private function iss(): string
    {
        return (empty($_SERVER['HTTPS']) ? 'http' : 'https') . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
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

    private function jti(): string
    {
        return base64_encode(random_bytes(16));
    }

    private function aud(): string
    {
        return (empty($_SERVER['HTTPS']) ? 'http' : 'https') . "://$_SERVER[HTTP_HOST]";
    }
}
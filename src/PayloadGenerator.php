<?php

namespace Kostyap\JwtAuth;

use Carbon\Carbon;
use DateTimeImmutable;
use Kostyap\JwtAuth\Exceptions\InvalidClaimsException;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\RegisteredClaims;

class PayloadGenerator
{
    private const CARBON_TIMEZONE = 'UTC';

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
    public function getBuilderWithClaims(): Builder
    {
        $tokenBuilder = (new Builder(new JoseEncoder(), ChainedFormatter::default()));

        foreach ($this->claims as $claim) {
            match ($claim) {
                RegisteredClaims::ISSUED_AT => $tokenBuilder->issuedAt($this->iat()),
                RegisteredClaims::EXPIRATION_TIME => $tokenBuilder->expiresAt($this->exp()),
                RegisteredClaims::NOT_BEFORE => $tokenBuilder->canOnlyBeUsedAfter($this->nbf()),
                RegisteredClaims::ID => $tokenBuilder->identifiedBy($this->jti()),
                RegisteredClaims::ISSUER => $tokenBuilder->issuedBy($this->iss()),
                //TODO
                RegisteredClaims::AUDIENCE => $tokenBuilder->permittedFor(''),
                //TODO
                RegisteredClaims::SUBJECT => $tokenBuilder->relatedTo(''),
                default => throw new InvalidClaimsException('Unexpected JWT default claim'),
            };
        }

        return $tokenBuilder;
    }

    private function iss(): string
    {
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
}
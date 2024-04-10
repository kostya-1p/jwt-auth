<?php

namespace Kostyap\JwtAuth\Jwt;

interface JWTSubject
{
    public function getJWTIdentifier(): mixed;

    /** @return array<non-empty-string, mixed> */
    public function getJWTCustomClaims(): array;
}
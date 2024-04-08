<?php

namespace Kostyap\JwtAuth\Jwt;

interface JWTSubject
{
    public function getJWTIdentifier(): mixed;

    /** @return array<int|string, mixed> */
    public function getJWTCustomClaims(): array;
}
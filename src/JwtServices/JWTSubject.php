<?php

namespace Kostyap\JwtAuth\JwtServices;

interface JWTSubject
{
    public function getJWTIdentifier(): mixed;

    /** @return array<non-empty-string, mixed> */
    public function getJWTCustomClaims(): array;
}
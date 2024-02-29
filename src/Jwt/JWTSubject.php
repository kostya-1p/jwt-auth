<?php

namespace Kostyap\JwtAuth\Jwt;

interface JWTSubject
{
    public function getJWTIdentifier(): mixed;

    public function getJWTCustomClaims(): array;
}
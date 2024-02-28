<?php

namespace Kostyap\JwtAuth;

interface JWTSubject
{
    public function getJWTIdentifier(): mixed;

    public function getJWTCustomClaims(): array;
}
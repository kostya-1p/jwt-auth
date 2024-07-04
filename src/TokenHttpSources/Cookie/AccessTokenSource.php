<?php

namespace Kostyap\JwtAuth\TokenHttpSources\Cookie;

class AccessTokenSource extends AbstractTokenSource
{
    protected function getTokenKey(): string
    {
        return self::ACCESS_TOKEN_KEY;
    }
}
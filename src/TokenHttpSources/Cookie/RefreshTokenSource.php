<?php

namespace Kostyap\JwtAuth\TokenHttpSources\Cookie;

class RefreshTokenSource extends AbstractTokenSource
{
    protected function getTokenKey(): string
    {
        return self::REFRESH_TOKEN_KEY;
    }
}
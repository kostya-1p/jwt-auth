<?php

namespace Kostyap\JwtAuth\Enum;

enum RefreshTokenSource: string
{
    case Cookie = 'cookie';
    case Body = 'body';
}

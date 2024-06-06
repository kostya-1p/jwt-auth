<?php

namespace Kostyap\JwtAuth\Enums;

enum RefreshTokenSource: string
{
    case Cookie = 'cookie';
    case Body = 'body';
}

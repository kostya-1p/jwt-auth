<?php

namespace Kostyap\JwtAuth\Enum;

enum AccessTokenSource: string
{
    case Cookie = 'cookie';
    case Bearer = 'bearer';
}

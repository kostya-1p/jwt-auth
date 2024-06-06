<?php

namespace Kostyap\JwtAuth\Enums;

enum AccessTokenSource: string
{
    case Cookie = 'cookie';
    case Bearer = 'bearer';
}

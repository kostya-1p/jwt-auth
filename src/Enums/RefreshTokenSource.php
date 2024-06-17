<?php

namespace Kostyap\JwtAuth\Enums;

use Kostyap\JwtAuth\TokenHttpSources\Body;
use Kostyap\JwtAuth\TokenHttpSources\Cookie;

enum RefreshTokenSource: string
{
    case Cookie = Cookie\RefreshTokenSource::class;
    case Body = Body\BodyRefreshTokenSource::class;
}

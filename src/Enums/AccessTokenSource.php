<?php

namespace Kostyap\JwtAuth\Enums;

use Kostyap\JwtAuth\TokenHttpSources\Body;
use Kostyap\JwtAuth\TokenHttpSources\Cookie;

enum AccessTokenSource: string
{
    case Cookie = Cookie\AccessTokenSource::class;
    case Bearer = Body\BearerAccessTokenSource::class;
}

<?php

namespace Kostyap\JwtAuth\Helpers;

use Kostyap\JwtAuth\Exceptions\RequestUrlException;

class RequestUrlHelper
{
    private const HOST_KEY = 'HTTP_HOST';
    private const URI_KEY = 'REQUEST_URI';

    private static function checkServerValueExistence(string $key): void
    {
        if (!isset($_SERVER[$key]) || !$_SERVER[$key]) {
            throw new RequestUrlException("Request $key not set!");
        }
    }

    public static function getCurrentHost(): string
    {
        self::checkServerValueExistence(self::HOST_KEY);
        return (empty($_SERVER['HTTPS']) ? 'http' : 'https') . '://' . $_SERVER[self::HOST_KEY];
    }

    public static function getCurrentUrl(): string
    {
        self::checkServerValueExistence(self::URI_KEY);
        $host = self::getCurrentHost();
        return $host . $_SERVER[self::URI_KEY];
    }
}
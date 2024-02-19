<?php

namespace Kostya1p\JwtAuth;

final class ExampleClass
{
    public string $property;

    public function __construct(string $property = 'test')
    {
        $this->property = $property;
    }

    public function getProperty(): string
    {
        return $this->property;
    }

    public function setProperty(string $property): void
    {
        $this->property = $property;
    }
}
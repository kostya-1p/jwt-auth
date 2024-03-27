<?php

namespace Kostyap\JwtAuth\Jwt\Generation;

use Kostyap\JwtAuth\Exceptions\SignatureAlgorithmException;
use Kostyap\JwtAuth\Exceptions\SignatureKeyException;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa;

class JWTSigner
{
    public const ALGO_HS256 = 'HS256';
    public const ALGO_HS384 = 'HS384';
    public const ALGO_HS512 = 'HS512';
    public const ALGO_RS256 = 'RS256';
    public const ALGO_RS384 = 'RS384';
    public const ALGO_RS512 = 'RS512';
    public const ALGO_ES256 = 'ES256';
    public const ALGO_ES384 = 'ES384';
    public const ALGO_ES512 = 'ES512';

    protected string $algo;
    protected Signer $JWTSigner;

    protected ?string $secret;
    protected ?string $publicKey;
    protected ?string $privateKey;

    protected array $signers = [
        self::ALGO_HS256 => Signer\Hmac\Sha256::class,
        self::ALGO_HS384 => Signer\Hmac\Sha384::class,
        self::ALGO_HS512 => Signer\Hmac\Sha512::class,
        self::ALGO_RS256 => Signer\Rsa\Sha256::class,
        self::ALGO_RS384 => Signer\Rsa\Sha384::class,
        self::ALGO_RS512 => Signer\Rsa\Sha512::class,
        self::ALGO_ES256 => Signer\Ecdsa\Sha256::class,
        self::ALGO_ES384 => Signer\Ecdsa\Sha384::class,
        self::ALGO_ES512 => Signer\Ecdsa\Sha512::class,
    ];

    public function __construct()
    {
        $this->algo = config('jwt.algo');
        $this->secret = config('jwt.secret');
        $this->publicKey = config('jwt.keys.public');
        $this->privateKey = config('jwt.keys.private');
    }

    public function getJWTSigner(): Signer
    {
        if (!array_key_exists($this->algo, $this->signers)) {
            throw new SignatureAlgorithmException('The given algorithm could not be found');
        }

        $signer = $this->signers[$this->algo];
        $this->JWTSigner = new $signer();
        return $this->JWTSigner;
    }

    public function getSigningKey(): Key
    {
        if ($this->isAsymmetric()) {
            if (!$this->privateKey) {
                throw new SignatureKeyException('Private key is not set.');
            }

            return $this->getKey($this->privateKey);
        }

        if (!$this->secret) {
            throw new SignatureKeyException('Secret key is not set.');
        }

        return $this->getKey($this->secret);
    }

    public function getVerificationKey(): Key
    {
        if ($this->isAsymmetric()) {
            if (!$this->publicKey) {
                throw new SignatureKeyException('Public key is not set.');
            }

            return $this->getKey($this->publicKey);
        }

        if (!$this->secret) {
            throw new SignatureKeyException('Secret key is not set.');
        }

        return $this->getKey($this->secret);
    }

    protected function isAsymmetric(): bool
    {
        return is_subclass_of($this->JWTSigner, Rsa::class)
            || is_subclass_of($this->JWTSigner, Ecdsa::class);
    }

    protected function getKey(string $contents, string $passphrase = ''): Key
    {
        return InMemory::plainText($contents, $passphrase);
    }
}
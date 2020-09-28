<?php

namespace FreedomSex\Services;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use InvalidArgumentException;

/**
 * Class TimeEncoder
 * @package FreedomSex\Services
 */
class TimeEncoder
{
    const EXPIRE_TIME = 15;

    public function __construct(string $secret = null, ?int $expire = null)
    {
        $this->timestamp = time();
        $this->expire = $expire ?? self::EXPIRE_TIME;
        $this->secret = $secret ?? getenv('APP_SECRET');
    }

    public function uuid()
    {
        $bytes = random_bytes(5);
        return bin2hex($bytes);
    }

    public function setExpire(int $seconds)
    {
        $this->expire = $seconds;
        return $this;
    }

    public function expire(int $seconds)
    {
        return $this->timestamp + $seconds + $this->expire;
    }

    public function wait(int $seconds)
    {
        return $this->timestamp + $seconds;
    }

    public function token(int $time, string $action = 'stop-them', ?string $audience = null)
    {
        $builder = new Builder();
        $signer = new Sha256();

        $token = $builder
            ->issuedAt($this->timestamp)
            ->canOnlyBeUsedAfter($this->wait($time))
            ->expiresAt($this->expire($time))
            ->withClaim('uid', $this->uuid())
            ->withClaim('time', $time)
            ->withClaim('action', $action);
        if ($audience) {
            $token->permittedFor($audience);
        }
        $token = $token->getToken($signer, new Key($this->secret));
        return $token;
    }

    public function checkout(string $jwt, ?string $audience = null)
    {
        $parser = new Parser();
        $signer = new Sha256();
        $key = new Key($this->secret);
        $data = new ValidationData();
        if ($audience) {
            $data->setAudience($audience);
        }
        try {
            $token = $parser->parse($jwt);
        } catch (InvalidArgumentException $e) {
            return false;
        }
        if (!$token->verify($signer, $key) or !$token->validate($data)) {
            return false;
        }
        return true;
    }
}

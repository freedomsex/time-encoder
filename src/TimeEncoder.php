<?php

namespace FreedomSex\Services;

use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Signer\Hmac\Sha256;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;

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
        $this->setConfiguration($secret);
    }

    public function setConfiguration(string $secret)
    {
        $this->lcobucciJWT = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::plainText($this->secret)
        );
    }

    public function setConstraints(?string $audience = null)
    {
        $date = new \DateTimeImmutable();
        $this->lcobucciJWT->setValidationConstraints(new SignedWith(
            $this->lcobucciJWT->signer(),
            $this->lcobucciJWT->signingKey()
        ));
        $this->lcobucciJWT->setValidationConstraints(new StrictValidAt(
            new FrozenClock($date)
        ));
        if ($audience) {
            $this->lcobucciJWT->setValidationConstraints(new PermittedFor($audience));
        }
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

    public function expire(\DateTimeImmutable $date, int $seconds)
    {
        $wait = $seconds + $this->expire;
        return $date->modify("$wait seconds");
    }

    public function wait(\DateTimeImmutable $date, int $seconds)
    {
        return $date->modify("$seconds seconds");
    }

    public function token(int $seconds, string $action = 'stop-them', ?string $audience = null)
    {
        $date = new \DateTimeImmutable();
        $token = $this->lcobucciJWT->builder()
            ->issuedAt($date)
            ->canOnlyBeUsedAfter($this->wait($date, $seconds))
            ->expiresAt($this->expire($date, $seconds))
            ->withClaim('uid', $this->uuid())
            ->withClaim('time', $seconds)
            ->withClaim('action', $action);
        if ($audience) {
            $token->permittedFor($audience);
        }
        $token = $token->getToken(
            $this->lcobucciJWT->signer(),
            $this->lcobucciJWT->signingKey()
        );
        return $token->toString();
    }

    public function parse(string $jwt)
    {
        try {
            $token = $this->lcobucciJWT->parser()->parse($jwt);
        } catch (InvalidTokenStructure $e) {
            return false;
        }
        return $token;
    }

    public function checkout(string $jwt, ?string $audience = null)
    {
        $token = $this->parse($jwt);
        $this->setConstraints($audience);
        $constraints = $this->lcobucciJWT->validationConstraints();
        try {
            $this->lcobucciJWT->validator()->assert($token, ...$constraints);
            $this->lcobucciJWT->validator()->validate($token, ...$constraints);
        } catch (RequiredConstraintsViolated $e) {
            return false;
        }
        return true;
    }
}

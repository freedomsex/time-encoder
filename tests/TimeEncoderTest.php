<?php

namespace FreedomSex\Services\Tests;

use FreedomSex\Services\TimeEncoder;
use PHPUnit\Framework\TestCase;

class TimeEncoderTest extends TestCase
{
    public function setUp(): void
    {
        parent::setUp();
        $this->object = new TimeEncoder('1234567890', 10);
    }

    public function testParse()
    {
        $token = $this->object->token(5);
        $data = $this->object->parse($token);
        self::assertTrue($data->claims()->has('time'));
    }

    public function testCheckout()
    {
        $token = $this->object->token(5);
        self::assertFalse($this->object->checkout($token));
        $token = $this->object->token(0);
        self::assertTrue($this->object->checkout($token));
    }

    public function testToken()
    {
        $token = $this->object->token(5);
        self::assertEquals(3, count(explode('.', $token)));
    }
}

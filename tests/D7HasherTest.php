<?php

namespace Kellerjmrtn\D7Password\Tests;

use Kellerjmrtn\D7Password\PasswordInc;
use PHPUnit\Framework\TestCase;

class D7HasherTest extends TestCase
{
    protected PasswordInc $hasher;

    protected function setUp(): void
    {
        $this->hasher = new PasswordInc();
    }

    public function test_it_creates_a_hash()
    {
        $hash = $this->hasher->user_hash_password('testpass');

        $this->assertEquals(PasswordInc::DRUPAL_HASH_LENGTH, strlen($hash));
    }

    public function test_it_validates_a_hash()
    {
        $hash = $this->hasher->user_hash_password('testpass');

        $this->assertTrue($this->hasher->user_check_password('testpass', $hash));
    }

    public function test_it_invalidates_a_hash()
    {
        $hash = $this->hasher->user_hash_password('testpass');

        $this->assertFalse($this->hasher->user_check_password('differentpass', $hash));
    }

    public function test_it_requires_rehash_for_invalid_hash()
    {
        $hash = str_replace('$S$', '###', $this->hasher->user_hash_password('testpass'));

        $this->assertTrue($this->hasher->user_needs_new_hash($hash));
    }

    public function test_it_does_not_require_rehash_for_valid_hash()
    {
        $hash = $this->hasher->user_hash_password('testpass');

        $this->assertFalse($this->hasher->user_needs_new_hash($hash));
    }
}

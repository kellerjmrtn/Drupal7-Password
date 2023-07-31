<?php

namespace Kellerjmrtn\D7Password\Interfaces;

/**
 * Interface defining an implementation of Drupal 7's password.inc file
 */
interface PasswordInc
{
    /**
     * Hash a password using a secure hash.
     *
     * @param $password
     *   A plain-text password.
     * @param $countLog2
     *   Optional integer to specify the iteration count. Generally used only during
     *   mass operations where a value less than the default is needed for speed.
     *
     * @return
     *   A string containing the hashed password (and a salt), or FALSE on failure.
     */
    public function user_hash_password(string $password, int $countLog2 = 0): string|false;

    /**
     * Check whether a plain text password matches a stored hashed password.
     *
     * @param $password
     *   A plain-text password
     * @param $hashedPassword
     *   The existing password hash to check against
     *
     * @return
     *   TRUE or FALSE.
     */
    public function user_check_password(string $password, string $hashedPassword): bool;

    /**
     * Check whether a user's hashed password needs to be replaced with a new hash.
     *
     * @param $hashedPassword
     *   The existing password hash to check against
     *
     * @return
     *   TRUE or FALSE.
     */
    public function user_needs_new_hash(string $hashedPassword): bool;
}

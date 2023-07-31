<?php

namespace Kellerjmrtn\D7Password;

use Exception;
use Kellerjmrtn\D7Password\Interfaces\PasswordInc as PasswordIncInterface;

/**
 * An class-based implementation of Drupal 7's password.inc file
 * 
 * Originally based on Drupal 7.98
 */
class PasswordInc implements PasswordIncInterface
{
    /**
     * The standard log2 number of iterations for password stretching. This should
     * increase by 1 every Drupal version in order to counteract increases in the
     * speed and power of computers available to crack the hashes.
     * 
     * @var int
     */
    public const DRUPAL_HASH_COUNT = 15;

    /**
     * The minimum allowed log2 number of iterations for password stretching.
     * 
     * @var int
     */
    public const DRUPAL_MIN_HASH_COUNT = 7;

    /**
     * The maximum allowed log2 number of iterations for password stretching.
     * 
     * @var int
     */
    public const DRUPAL_MAX_HASH_COUNT = 30;

    /**
     * The expected (and maximum) number of characters in a hashed password.
     * 
     * @var int
     */
    public const DRUPAL_HASH_LENGTH = 55;

    /**
     * A string for mapping an int to the corresponding base 64 character.
     * 
     * @var string
     */
    public const ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

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
    public function user_hash_password(string $password, int $countLog2 = 0): string|false
    {
        return $this->hash($password, $countLog2);
    }

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
    public function user_check_password(string $password, string $hashedPassword): bool
    {
        return $this->check($password, $hashedPassword);
    }

    /**
     * Check whether a user's hashed password needs to be replaced with a new hash.
     *
     * @param $hashedPassword
     *   The existing password hash to check against
     *
     * @return
     *   TRUE or FALSE.
     */
    public function user_needs_new_hash(string $hashedPassword): bool
    {
        return $this->needsRehash($hashedPassword);
    }

    /**
     * Hash a password using a secure hash.
     *
     * @param string $password A plain-text password
     * @param int $countLog2 Optional iteration count
     * @return string|false
     */
    public function hash(string $password, int $countLog2 = 0): string|false
    {
        if (empty($countLog2)) {
            // Use the standard iteration count.
            $countLog2 = static::DRUPAL_HASH_COUNT;
        }

        return $this->passwordCrypt('sha512', $password, $this->generateSalt($countLog2));
    }

    /**
     * Check whether a plain text password matches a stored hashed password.
     *
     * @param string $password A plain-text password
     * @param string $hashedPassword The existing password hash to check against
     * @return bool
     */
    public function check(string $password, string $hashedPassword): bool
    {
        if (substr($hashedPassword, 0, 2) == 'U$') {
            // This may be an updated password from user_update_7000(). Such hashes
            // have 'U' added as the first character and need an extra md5().
            $storedHash = substr($hashedPassword, 1);
            $password = md5($password);
        } else {
            $storedHash = $hashedPassword;
        }
    
        switch (substr($storedHash, 0, 3)) {
            case '$S$':
                // A normal Drupal 7 password using sha512.
                $hash = $this->passwordCrypt('sha512', $password, $storedHash);
                break;
            case '$H$':
                // phpBB3 uses "$H$" for the same thing as "$P$".
            case '$P$':
                // A phpass password generated using md5.  This is an
                // imported password or from an earlier Drupal version.
                $hash = $this->passwordCrypt('md5', $password, $storedHash);
                break;
            default:
                return false;
        }

        return ($hash && $storedHash == $hash);
    }

    /**
     * Check whether a user's hashed password needs to be replaced with a new hash.
     *
     * This is typically called during the login process when the plain text
     * password is available. A new hash is needed when the desired iteration count
     * has changed through a change in the DRUPAL_HASH_COUNT or if the user's password
     * hash was generated in an update like user_update_7000().
     *
     * @param string $hashedPassword
     * @return bool
     */
    public function needsRehash(string $hashedPassword): bool
    {
        // Check whether this was an updated password.
        if ((substr($hashedPassword, 0, 3) != '$S$') || (strlen($hashedPassword) != static::DRUPAL_HASH_LENGTH)) {
            return true;
        }

        // Ensure that $countLog2 is within set bounds.
        $countLog2 = $this->enforceLog2Boundaries(static::DRUPAL_HASH_COUNT);

        // Check whether the iteration count used differs from the standard number.
        return $this->getCountLog2($hashedPassword) !== $countLog2;
    }

    /**
     * Hash a password using a secure stretched hash.
     *
     * By using a salt and repeated hashing the password is "stretched". Its
     * security is increased because it becomes much more computationally costly
     * for an attacker to try to break the hash by brute-force computation of the
     * hashes of a large number of plain-text words or strings to find a match.
     * 
     * Returns a string containing the hashed password (and salt) or false on failure.
     * The return string will be truncated at DRUPAL_HASH_LENGTH characters max.
     *
     * @param string $algo
     * @param string $password
     * @param string $setting
     * @return string|false
     */
    protected function passwordCrypt(string $algo, string $password, string $setting): string|false
    {
        // Prevent DoS attacks by refusing to hash large passwords.
        if (strlen($password) > 512) {
            return false;
        }

        // The first 12 characters of an existing hash are its setting string.
        $setting = substr($setting, 0, 12);

        if ($setting[0] != '$' || $setting[2] != '$') {
            return false;
        }

        $countLog2 = $this->getCountLog2($setting);

        // Hashes may be imported from elsewhere, so we allow != DRUPAL_HASH_COUNT
        if ($countLog2 < static::DRUPAL_MIN_HASH_COUNT || $countLog2 > static::DRUPAL_MAX_HASH_COUNT) {
            return false;
        }

        $salt = substr($setting, 4, 8);

        // Hashes must have an 8 character salt.
        if (strlen($salt) != 8) {
            return false;
        }

        // Convert the base 2 logarithm into an integer.
        $count = 1 << $countLog2;

        // We rely on the hash() function being available in PHP 5.2+.
        $hash = hash($algo, $salt . $password, true);

        do {
            $hash = hash($algo, $hash . $password, true);
        } while (--$count);

        $len = strlen($hash);
        $output =  $setting . $this->base64Encode($hash, $len);

        // _password_base64_encode() of a 16 byte MD5 will always be 22 characters.
        // _password_base64_encode() of a 64 byte sha512 will always be 86 characters.
        $expected = 12 + ceil((8 * $len) / 6);

        return (strlen($output) == $expected)
            ? substr($output, 0, static::DRUPAL_HASH_LENGTH) 
            : false;
    }

    /**
     * Parse the log2 iteration count from a stored hash or setting string.
     *
     * @param string $setting
     * @return int|false
     */
    protected function getCountLog2(string $setting): int|false
    {
        return strpos(static::ITOA64, $setting[3]);
    }

    /**
     * Encodes bytes into printable base 64 using the *nix standard from crypt().
     *
     * @param string $input
     * @param int $count
     * @return string
     */
    protected function base64Encode(string $input, int $count): string
    {
        $output = '';
        $i = 0;

        do {
            $value = ord($input[$i++]);
            $output .= static::ITOA64[$value & 0x3f];

            if ($i < $count) {
                $value |= ord($input[$i]) << 8;
            }

            $output .= static::ITOA64[($value >> 6) & 0x3f];

            if ($i++ >= $count) {
                break;
            }

            if ($i < $count) {
                $value |= ord($input[$i]) << 16;
            }

            $output .= static::ITOA64[($value >> 12) & 0x3f];

            if ($i++ >= $count) {
                break;
            }

            $output .= static::ITOA64[($value >> 18) & 0x3f];
        } while ($i < $count);

        return $output;
    }

    /**
     * Generates a random base 64-encoded salt prefixed with settings for the hash.
     *
     * @param int $countLog2
     * @return string
     */
    protected function generateSalt(int $countLog2): string
    {
        $output = '$S$';

        // Ensure that $countLog2 is within set bounds.
        $countLog2 = $this->enforceLog2Boundaries($countLog2);

        // We encode the final log2 iteration count in base 64.
        $output .= static::ITOA64[$countLog2];

        // 6 bytes is the standard salt for a portable phpass hash.
        $output .= $this->base64Encode($this->randomBytes(6), 6);

        return $output;
    }

    /**
     * Ensures that $countLog2 is within set bounds.
     *
     * @param int $countLog2
     * @return int
     */
    protected function enforceLog2Boundaries(int $countLog2): int
    {
        if ($countLog2 < static::DRUPAL_MIN_HASH_COUNT) {
            return static::DRUPAL_MIN_HASH_COUNT;
        } elseif ($countLog2 > static::DRUPAL_MAX_HASH_COUNT) {
            return static::DRUPAL_MAX_HASH_COUNT;
        }
        
        return $countLog2;
    }

    /**
     * Returns a string of highly randomized bytes (over the full 8-bit range).
     * 
     * NOTE: The D7 implementation of this function (drupal_random_bytes in bootstrap.inc) attempts
     *       to proxy to random_bytes if the function exists, and only attempts extra functionality
     *       if it doesn't. Since this package requires PHP 8, we can assume it always exists
     *
     * @param int $count
     * @throws Exception
     * @return string
     */
    protected function randomBytes(int $count): string
    {
        return random_bytes($count);
    }
}

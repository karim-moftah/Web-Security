<?php


class User{
    public $id;
    public $name;
    public $role;

    public function __construct($id, $name, $role) {

        $this->id = $id;
        $this->name = $name;
        $this->role = $role;
    }

}  

$user = new User("1", "karim", "user");


if(!isset($_COOKIE['user'])){
    $serializedUser = serialize($user);
    $encodedUser = base64_encode($serializedUser);
    setcookie('user', $encodedUser);
}
else if(isset($_COOKIE['user'])){
    $decodedUser = urldecode(base64_decode($_COOKIE['user']));
    $unserializedUser = unserialize($decodedUser);

    if($unserializedUser->role == 'admin'){
        echo("<h1>welcome " . htmlspecialchars($unserializedUser->name) . "</h1>");  
        echo "<h2>" . "FLAG{S3r14liz47i0n_M4573r}" . "</h2>";
    }else{
        echo("<h1>welcome " . htmlspecialchars($unserializedUser->name) . "</h1>");  
    }

}



?>
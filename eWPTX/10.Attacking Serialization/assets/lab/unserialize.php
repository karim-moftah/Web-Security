<?php

class User{
    public $first_name = 'karim';
    public $last_name = 'mohammed';

    public function __wakeup(){
        echo "<br>wakeup<br>";
    }


}  

$user = new User();

$serializedUser = serialize($user); // O:4:"User":2:{s:10:"first_name";s:5:"karim";s:9:"last_name";s:8:"mohammed";}

$unserializedUser = unserialize($serializedUser);

echo $unserializedUser->first_name;
echo "<br>";
echo $unserializedUser->last_name;
echo "<br>";
print_r($unserializedUser);
echo "<br>";
var_dump($unserializedUser);


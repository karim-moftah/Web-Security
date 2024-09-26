<?php

class User{
    public $first_name = 'karim';
    public $last_name = 'mohammed';

    public function __construct(){
        echo "constructor<br>";
    }
    public function __destruct(){
        echo "<br>destructor<br>";
    }

}  

$user = new User();
echo $user->first_name;
echo "<br>";
echo $user->last_name;
echo "<br>";

$serialized_firstname = serialize($user->first_name);
echo $serialized_firstname;
echo "<br>";
$serializedUser = serialize($user);
echo $serializedUser;






?>
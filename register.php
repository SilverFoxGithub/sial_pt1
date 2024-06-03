<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require 'vendor/autoload.php';
include 'connect.php';

if($_SERVER["REQUEST_METHOD"]=="POST") {
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    $name = filter_input(INPUT_POST, 'name', FILTER_SANITIZE_STRING);
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $password = password_hash(filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING), PASSWORD_BCRYPT);
    $token = bin2hex(random_bytes(50));

    $sql = "INSERT INTO users_tbl (username, name, email, password, token) VALUES (:username, :name, :email, :password, :token)";
    $stmt = $conn->prepare($sql);

    try {
        $stmt->execute([
            ':username' => $username,
            ':name' => $name,
            ':email' => $email,
            ':password' => $password,
            ':token' => $token,
        ]);

        $mail = new PHPMailer(true);
        try {
            $mail->isSMTP();
            $mail->Host = 'localhost';
            $mail->SMPTAuth = false;
            $mail->Port = 1025;

            $mail->setFrom('no-reply@yourdomain.com', 'Mailer');
            $mail->addAddress($email, $username);

            $mail->isHTML(true);
            $mail->Subject = 'Email Verification';
            $mail->Body = 'Click on the link to verify your email: <a href="http://localhost/deluna/verify.php?token=' .$token. '">Verify Email</a>';
            
            $mail->send();
            echo 'Registration successful, Please check your email for the verification link.';
        } catch (Exception $e) {
            echo "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
        }
    } catch (PDOException $e) {
        echo "Error: " .$e->getMessage();
    }
}
?>
<?php
include 'connect.php';

if (isset($_GET['token'])) {
    $token = filter_input(INPUT_GET, 'token', FILTER_SANITIZE_STRING);

    if ($token) {
        $stmt = $conn->prepare("SELECT * FROM users_tbl WHERE token = :token LIMIT 1");
        $stmt->bindParam(':token', $token);

        try {
            $stmt->execute();
            if ($stmt->rowCount() > 0) {
                $user = $stmt->fetch(PDO::FETCH_ASSOC);

                $updateStmt = $conn->prepare("UPDATE users_tbl SET is_verified = 1 WHERE token = :token");
                $updateStmt->bindParam(':token', $token);

                if ($updateStmt->execute()) {
                    echo "Your email has been verified. You can now login.";
                } else {
                    echo "Error updating record.";
                }
            } else {
                echo "This verification token is invalid.";
            }
        } catch (PDOException $e) {
            echo "Error: " .$se->getMessage();
        }
    } else {
        echo "Invalid token.";
    }
}

$conn = null;
?>
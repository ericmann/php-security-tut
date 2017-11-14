<?php

use Slim\Http\Request;
use Slim\Http\Response;
use PHPMailer\PHPMailer\PHPMailer;

// Helpers

/**
 * Get or create a random HMAC key for users setting up 2FA devices.
 *
 * @param string                $email
 * @param Flintstone\Flintstone $db
 *
 * @return string
 */
function get_totp_token($email, $db)
{
    $user_data = json_decode($db->get(bin2hex($email)), true);
    if (isset( $user_data['totp_key'])) {
        return $user_data['totp_key'];
    }

    $key = generate_key();
    $user_data['totp_key'] = $key;

    $db->set(bin2hex($email), json_encode($user_data));
    return $key;
}

/**
 * Generates key
 *
 * @param int $bitsize Nume of bits to use for key.
 *
 * @return string $bitsize long string composed of available base32 chars.
 */
function generate_key( $bitsize = 128 ) {
    $base_32_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    $s 	= '';

    for ( $i = 0; $i < $bitsize / 8; $i++ ) {
        $s .= $base_32_chars[ rand( 0, 31 ) ];
    }

    return $s;
}

// Routes

/**
 * Get the standard login splash page
 */
$app->get('/', function (Request $request, Response $response, array $args) {
    $error = $request->getQueryParam('error');
    if (!empty($this->errors[ $error ])) {
        $args[ 'error' ] = $this->errors[ $error ];
        $this->logger->error($args[ 'error' ]);
    }
    $message = $request->getQueryParam('message');
    if (!empty($this->messages[ $message ])) {
        $args[ 'message' ] = $this->messages[ $message ];
    }

    // Render index view
    return $this->renderer->render($response, 'index.phtml', $args);
});

/**
 * Get the new account registration page
 */
$app->get('/register', function ($request, $response, $args) {
    $error = $request->getQueryParam('error');
    if (!empty($this->errors[ $error ])) {
        $args[ 'error' ] = $this->errors[ $error ];
        $this->logger->error($args[ 'error' ]);
    }

    // Render registration view
    return $this->renderer->render($response, 'register.phtml', $args);
});

/**
 * Process a new registration
 */
$app->post('/register', function ($request, $response, $args) {
    $fname = $request->getParam('fname');
    $lname = $request->getParam('lname');
    $email = $request->getParam('email');
    $password = $request->getParam('password');
    $cpassword = $request->getParam('password_confirm');

    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $this->logger->error('Empty or invalid email address');
        return $response->withRedirect('/register?error=emptyemail');
    }
    if ($this->users->get(bin2hex($email))) {
        $this->logger->error(sprintf('Duplicate email %s', $email));
        return $response->withRedirect('/register?error=useduser');
    }
    if (!hash_equals($password, $cpassword)) {
        return $response->withRedirect('/register?error=nomatch');
    }
    $user = [
        'email' => $email,
        'balance' => random_int(0, 10), // Start off with a random gift balance ...
        'firstName' => $fname,
        'lastName' => $lname,
        'password' => password_hash($password, PASSWORD_DEFAULT),
        'totp_key' => generate_key()
    ];
    $this->users->set(bin2hex($email), json_encode($user));
    $_SESSION[ 'email' ] = $email;
    return $response->withRedirect('/profile?message=2fa');
});

/**
 * Process a login attempt
 */
$app->any('/login', function ($request, $response, $args) {
})->add(new PasswordAuthentication($container));

/**
 * Get the password recovery page
 */
$app->get('/recovery', function ($request, $response, $args) {
    $error = $request->getQueryParam('error');
    if (!empty($this->errors[ $error ])) {
        $args[ 'error' ] = $this->errors[ $error ];
        $this->logger->error($args[ 'error' ]);
    }
    $message = $request->getQueryParam('message');
    if (!empty($this->messages[ $message ])) {
        $args[ 'message' ] = $this->messages[ $message ];
    }

    // Render index view
    return $this->renderer->render($response, 'recovery.phtml', $args);
});

/**
 * Process an account recovery action
 */
$app->post('/recovery', function ($request, $response, $args) {
    $email = $request->getParam('email');

    // Ensure the user exists first
    if ($this->users->get(bin2hex($email))) {
        // Create a reset token for the user and store in the database
        $token = bin2hex(random_bytes(32));
        $lookup = substr($token, 0,32);
        $verifier = substr($token, 32);

        $this->tokens->set($lookup, [password_hash($verifier, PASSWORD_DEFAULT), $email, time()]);

        // Use PHPMailer to dispatch the token to the user
        $reset_link = sprintf('http://localhost:8080/reset?token=%s', $token);
        $mail = new PHPMailer(true);
        try {
            // Server settings
            $mail->SMTPDebug = 2;                  // Enable verbose debug output
            $mail->isSMTP();                       // Set mailer to use SMTP
            $mail->Host = 'localhost';             // Specify SMTP servers
            $mail->Username = 'admin@rngcoin.com'; // SMTP username
            $mail->Password = 'secret';            // SMTP password
            $mail->Port = 1025;                    // TCP port to connect to

            // Recipients
            $mail->setFrom('admin@rngcoin.com', 'RNGCoin');
            $mail->addAddress($email);     // Add a recipient

            // Content
            $mail->isHTML(true);                                  // Set email format to HTML
            $mail->Subject = 'Reset your RNGCoin Password';
            $mail->Body    = sprintf('Click <a href="%s">this link</a> to reset your password.', $reset_link);
            $mail->AltBody = sprintf('Click this link to reset your password: %s', $reset_link);

            $mail->send();
        } catch (Exception $e) {
            $this->logger->error($mail->ErrorInfo);
            return $response->withRedirect('/?error=mailerror');
        }
    }

    // Redirect to the login page and inform the user an email is on the way
    return $response->withRedirect('/?message=checkemail');
});

/**
 * Process an incoming recovery token
 */
$app->get('/reset', function ($request, $response, $args) {
    $token = $request->getQueryParam('token');

    // Validate the reset token
    $lookup = substr($token, 0, 32);
    $verify = substr($token, 32);
    $token_data = $this->tokens->get($lookup);

    if (password_verify($verify, $token_data[0]) ) {
        // Make sure it's less than 15 minutes old
        if (time() < ($token_data[2] + 60 * 15)) {
            // Set up a temporary reset session
            $_SESSION['reset_for'] = $token_data[1];

            // Delete the token
            $this->tokens->delete($lookup);

            return $this->renderer->render($response, 'reset.phtml', $args);
        }
    }

    return $response->withRedirect('/?error=invalidreset');
});

/**
 * Process the reset token and request a 2fa code
 */
$app->post('/reset', function($request, $response, $args) {
    $token = $request->getParam('2fa');
    $email = $_SESSION['reset_for'];

    if ($user = $this->users->get(bin2hex($email))) {
        $user_data = json_decode($user, true);
        if (PasswordAuthentication::is_valid_authcode($user_data['totp_key'], $token)) {
            // Transparently log the user in
            $_SESSION['email'] = $email;

            // Redirect to the profile page for account changes
            return $response->withRedirect('/profile?message=resetpassword');
        }
    }

    return $response->withRedirect('/?error=invalidreset');
});

/**
 * Get a user's logged-in dashboard
 */
$app->get('/dashboard', function ($request, $response, $args) {
    if (!isset($_SESSION[ 'email' ]) || !($user_data = $this->users->get(bin2hex($_SESSION[ 'email' ])))) {
        $this->logger->error('Unauthorized access to dashboard');
        return $response->withRedirect('/?error=notloggedin');
    }
    $error = $request->getQueryParam('error');
    if (!empty($this->errors[ $error ])) {
        $args[ 'error' ] = $this->errors[ $error ];
        $this->logger->error($args[ 'error' ]);
    }
    $message = $request->getQueryParam('message');
    if (!empty($this->messages[ $message ])) {
        $args[ 'message' ] = $this->messages[ $message ];
    }

    $user = json_decode($user_data, true);
    $args[ 'fName' ] = $user[ 'firstName' ];
    $args[ 'lName' ] = $user[ 'lastName' ];
    $args[ 'balance' ] = $user[ 'balance' ];

    $value = $this->coins->get('value');

    if (!$value) {
        $value = 1;
    }
    $args[ 'value' ] = $value;
    $dollars = $args[ 'balance' ] * $value;

    $args[ 'dollars' ] = floor($dollars * 1000) / 1000;

    return $this->renderer->render($response, 'dashboard.phtml', $args);
});

/**
 * Get a user's profile page
 */
$app->get('/profile', function ($request, $response, $args) {
    if (!isset($_SESSION[ 'email' ]) || !($user_data = $this->users->get(bin2hex($_SESSION[ 'email' ])))) {
        $this->logger->error('Unauthorized access to profile');
        return $response->withRedirect('/?error=notloggedin');
    }
    $error = $request->getQueryParam('error');
    if (!empty($this->errors[ $error ])) {
        $args[ 'error' ] = $this->errors[ $error ];
        $this->logger->error($args[ 'error' ]);
    }
    $message = $request->getQueryParam('message');
    if (!empty($this->messages[ $message ])) {
        $args[ 'message' ] = $this->messages[ $message ];
    }

    $user = json_decode($user_data, true);
    $args[ 'fName' ] = $user[ 'firstName' ];
    $args[ 'lName' ] = $user[ 'lastName' ];
    $args[ 'email' ] = $user[ 'email' ];
    $args[ 'totp_key' ] = get_totp_token( $args[ 'email' ], $this->users );

    return $this->renderer->render($response, 'profile.phtml', $args);
});

/**
 * Process any profile updates
 */
$app->post('/profile', function ($request, $response, $args) {
    $fname = $request->getParam('fname');
    $lname = $request->getParam('lname');
    $email = $request->getParam('email');
    $password = $request->getParam('password');
    $cpassword = $request->getParam('password_confirm');

    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $this->logger->error('Empty or invalid email address');
        return $response->withRedirect('/profile?error=emptyemail');
    }

    if (!empty($password) && !hash_equals($password, $cpassword)) {
        return $response->withRedirect('/profile?error=nomatch');
    }

    // Update the user
    $user = json_decode($this->users->get(bin2hex($_SESSION[ 'email' ])), true);
    $user[ 'firstName' ] = $fname;
    $user[ 'lastName' ] = $lname;
    $user[ 'password' ] = password_hash($password, PASSWORD_DEFAULT);

    if (hash_equals($email, $_SESSION[ 'email' ])) {
        $this->users->set(bin2hex($_SESSION[ 'email' ]), json_encode($user));
    } else {
        if ($this->users->get(bin2hex($email))) {
            return $response->withRedirect('/profile?error=useduser');
        }

        $user[ 'email' ] = $email;
        $this->users->set(bin2hex($email), json_encode($user));
        $this->users->delete(bin2hex($_SESSION[ 'email' ]));
        $_SESSION[ 'email' ] = $email;
    }

    return $response->withRedirect('/profile?message=updated');
});

/**
 * Get the current value of our random cryptocurrency ...
 */
$app->get('/value', function ($request, $response, $args) {
    $value = $this->coins->get('value');

    if (!$value) {
        $value = 1;
    }

    $updown = random_int(0, 10) % 2 ? -1 : 1;
    $amount = random_int(0, 10) / 1000;

    $value += $updown * $amount;
    $this->coins->set('value', $value);

    $response->getBody()->write($value);

    return $response;
});

/**
 * Logging out is a matter of clearing the PHP session and redirecting to the homepage.
 */
$app->get('/logout', function ($request, $response, $args) {
    session_destroy();
    return $response->withRedirect('/?message=loggedout');
});

/**
 * Handle buying/selling transactions
 */
$app->post('/transact', function ($request, $response, $args) {
    $dollars = $request->getParam('dollars_in');
    $coin = $request->getParam('coin_out');

    $user = json_decode($this->users->get(bin2hex($_SESSION[ 'email' ])), true);
    $balance = floatval($user[ 'balance' ]);

    // Handle coin sales _first_
    if (!empty($coin) && floatval($coin) > $balance) {
        $response->getBody()->write(json_encode(['error' => 'nsf']));

        return $response;
    } else {
        $balance -= floatval($coin);
    }

    // Handle coin purchases
    if (! empty($dollars)) {
        $value = $this->coins->get('value');

        if (!$value) {
            $value = 1;
        }

        $balance += floatval($dollars) / $value;
    }

    // Update the balance in a pending session
    $_SESSION['new_balance'] = $balance;

    // Instantiate a Tozny challenge
    $challenge = $this->tozny->questionChallenge('Do you authorize a purchase/sale of RNGCoin?', '');

    // Push the Tozny challenge
    $args = array(
        'method'     => 'realm.user_push',
        'user_id'    => '',
        'session_id' => $challenge['session_id']
    );
    $this->tozny->rawCall($args);

    $response->getBody()->write(json_encode($challenge));
    return $response;
});

$app->get('/status/[{session}]', function ($request, $response, $args) {
    $status = $this->tozny_user->checkSessionStatus($args['session']);

    if (array_key_exists('status', $status) && $status['status'] === "pending") {
        $response->getBody()->write(json_encode($status));
        return $response;
    } else {
        $user = json_decode($this->users->get(bin2hex($_SESSION[ 'email' ])), true);
        $balance = $_SESSION['new_balance'];

        $user['balance'] = $balance;
        $this->users->set(bin2hex($_SESSION['email']), json_encode($user));

        $return = [
            'val'     => $this->coins->get('value'),
            'balance' => $balance
        ];

        $response->getBody()->write(json_encode($return));

        return $response;
    }
});
<?php

use Slim\Http\Request;
use Slim\Http\Response;

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
        'password' => password_hash($password, PASSWORD_DEFAULT)
    ];
    $this->users->set(bin2hex($email), json_encode($user));
    $_SESSION[ 'email' ] = $email;
    return $response->withRedirect('/dashboard');
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

    // @TODO Create a reset token for the user and store in the database
    // $this->tokens->set() ...

    // @TODO Use PHPMailer to dispatch the token to the user

    // Redirect to the login page and inform the user an email is on the way
    return $response->withRedirect('/?message=checkemail');
});

/**
 * Process an incoming recovery token
 */
$app->get('/reset', function ($request, $response, $args) {
    $token = $request->getQueryParam('token');

    // @TODO Validate the reset token

    // @TODO Transparently log the user in
    // $_SESSION['email'] = '...';

    // Redirect to the profile page for account changes
    return $response->withRedirect('/profile?message=resetpassword');
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
    $user[ 'password' ] = password_hash($password, PASSWORD_DEFAULT); // @TODO what should be stored here?

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
        return $response->withRedirect('/dashboard?error=nsf');
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

    // Update the balance
    $user[ 'balance' ] = $balance;
    $this->users->set(bin2hex($_SESSION[ 'email' ]), json_encode($user));

    return $response->withRedirect('/dashboard?message=transactioncomplete');
});
<?php

use Slim\Http\Request;
use Slim\Http\Response;

// Routes

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

$app->get('/register', function ($request, $response, $args) {
    $error = $request->getQueryParam('error');
    if (!empty($this->errors[ $error ])) {
        $args[ 'error' ] = $this->errors[ $error ];
        $this->logger->error($args[ 'error' ]);
    }

    // Render registration view
    return $this->renderer->render($response, 'register.phtml', $args);
});

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
        'password' => '' // @TODO What should be stored here?
    ];
    $this->users->set(bin2hex($email), json_encode($user));
    $_SESSION[ 'email' ] = $email;
    return $response->withRedirect('/dashboard');
});

$app->any('/login', function ($request, $response, $args) {
})->add(new PasswordAuthentication($container));

$app->get('/recovery', function($request, $response, $args) {
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

$app->post('/recovery', function($request, $response, $args) {
    $email = $request->getParam('email');
    
    return $response->withRedirect('/?checkemail');
});

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
    $args[ 'dollars' ] = $args[ 'balance' ] * $value;

    return $this->renderer->render($response, 'dashboard.phtml', $args);
});

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
    $user['firstName'] = $fname;
    $user['lastName'] = $lname;
    $user['password'] = ''; // @TODO what should be stored here?

    if(hash_equals($email, $_SESSION['email'])) {
        $this->users->set(bin2hex($_SESSION['email']), json_encode($user));
    } else {
        $user['email'] = $email;
        $this->users->set(bin2hex($email), json_encode($user));
        $this->users->delete(bin2hex($_SESSION['email']));
        $_SESSION['email'] = $email;
    }

    return $response->withRedirect('/profile?updated');
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
$app->get('/logout', function($request, $response, $args) {
    session_destroy();
    return $response->withRedirect('/?loggedout');
} );
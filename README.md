Coercive Session
================

Start and store basic items in session

Get
---
```
composer require coercive/session
```

Usage
-----
```php
use Coercive\Security\Session\Config;
use Coercive\Security\Session\Session;

# Set your config options
$Config = new Config();
$Config->setAutoStartSession(true);
$Config->setSessionDomain('.mywebsite.com');
//...

# Get your session handler
$Session = new Session($Config);

# And use ...
if($Session->isActive()) {
	// do something
}
```

Alianovna
---------
```php
use Coercive\Security\Cookie\Cookie;
use Coercive\Security\Session\Alianovna;

# Example of loading class Cookie
$crypt = 'exampleAbCdE12345';
$salt = 'example123';
$cookie = (new Cookie($crypt, '/', '.domain.com', true, true))
                ->anonymize(true, $salt);

# Example of loading class Alianovna
$crypt = 'example1234567890ABCDEF';
$dir = '/www/secure/directory/alianovna';
$alianovna = new Alianovna($crypt, $dir, $cookie);

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# For the first time, the internal directories must be created
# You can use the absolute reinit function :
$alianovna->kill();

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# Initialize Alianova for the current user
$alianovna->create();

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# Load session and show data
$alianovna->read();
var_dump($alianovna->data());
var_dump($alianovna->get('user'));
var_dump($alianovna->get('token'));
var_dump($alianovna->get('test'));

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# Save data
$alianovna->save([
    'user' => 123,
    'token' => 456,
    'test' => 'hello',
]);

# Or
$alianovna->data([
    'user' => 123,
    'token' => 456,
    'test' => 'hello',
]);
$alianovna->save();

# Or
$alianovna->set('user', 123);
$alianovna->set('token', 456);
$alianovna->set('test', 'hello');
$alianovna->save();

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# Refresh regstry tokens and cookies
$alianovna->refresh();

# Delete current user session
$alianovna->destroy();

# Delete all expired session
$alianovna->offload();

```

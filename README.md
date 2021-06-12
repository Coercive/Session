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
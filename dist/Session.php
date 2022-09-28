<?php
namespace Coercive\Security\Session;

use DateTime;
use Exception;

/**
 * Session
 *
 * @package 	Coercive\Security\Session
 * @link		https://github.com/Coercive/Session
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   2019 Anthony Moral
 * @license 	MIT
 */
class Session
{
	private Config $config;

	private Redirect $redirect;

	private User $user;

	/**
	 * Vérifie la validité de l'ID de session
	 *
	 * @return bool
	 */
	private function isValidId(): bool
	{
		return preg_match('/^[-,a-zA-Z0-9]{1,128}$/', session_id()) > 0;
	}

	/**
	 * Session constructor.
	 *
	 * @param Config $conf
	 * @return void
	 * @throws Exception
	 */
	public function __construct(Config $conf)
	{
		$this->config = $conf;

		# Start session with verification
		if($conf->isAutoStartSession()) {
			$this->startSession();
		}

		# Redirect
		$this->redirect = new Redirect($this);

		# User
		$this->user = new User($this);
	}

	/**
	 * GET CONFIG
	 *
	 * @return Config
	 */
	public function Config(): Config
	{
		return $this->config;
	}

	/**
	 * GET REDIRECT
	 *
	 * @return Redirect
	 */
	public function Redirect(): Redirect
	{
		return $this->redirect;
	}

	/**
	 * GET USER
	 *
	 * @return User
	 */
	public function User(): User
	{
		return $this->user;
	}

	/**
	 * IS SESSION ACTIVE
	 *
	 * @return bool
	 */
	public function isActive(): bool
	{
		return session_status() === PHP_SESSION_ACTIVE && session_id() !== '' && $this->isValidId();
	}

	/**
	 * START SESSION
	 *
	 * @return $this
	 * @throws Exception
	 */
	public function startSession(): Session
	{
		# Do not start if already active
		if($this->isActive()) { return $this; }

		# Prepare config ini set options
		foreach ($this->config->getIni() as $name => $value)
		{
			if(is_bool($value)) {
				$value = $value ? '1' : '0';
			}
			else {
				$value = strval($value);
			}
			ini_set($name, $value);
		}

		# Start session
		if(!@session_start()) {
			session_destroy();
			if(!session_start()) {
				throw new Exception("Can't start session.");
			}
		}

		# Maintain chainability
		return $this;
	}

	/**
	 * SET SESSION DATE
	 *
	 * @param DateTime $date
	 * @return $this
	 */
	public function setSessionDate(DateTime $date): Session
	{
		$this->Config()->setDate($date);
		return $this;
	}

	/**
	 * GETTER SESSION ID
	 *
	 * @return string
	 */
	public function getSessionId(): string
	{
		return $this->isActive() ? session_id() : '';
	}

	/**
	 * REGENERATE SESSION ID
	 *
	 * @return $this
	 */
	public function regenerateId(): Session
	{
		if($this->isActive()) {
			session_regenerate_id();
		}
		return $this;
	}
}

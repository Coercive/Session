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
	/** @var Config */
	private $config = null;

	/** @var DateTime */
	private $date = null;

	/** @var Redirect */
	private $redirect = null;

	/** @var User */
	private $user = null;

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
	 * @return void
	 * @throws Exception
	 */
	public function __construct(Config $conf)
	{
		# Ini set custom session domain
		if(null !== ($sessionDomain = $conf->getSessionDomain())) {
			$this->setSessionDomain($sessionDomain);
		}

		# Ini set custom cookie domain
		if(null !== ($cookieDomain = $conf->getCookieDomain())) {
			$this->setCookieDomain($cookieDomain);
		}

		# Ini set custom session path
		if(null !== ($sessionPath = $conf->getSessionPath())) {
			$this->setSessionPath($sessionPath);
		}

		# Ini set custom session name
		if(null !== ($sessionName = $conf->getSessionName())) {
			$this->setSessionName($sessionName);
		}

		# Ini set session max life time
		if(null !== ($sessionMaxTime = $conf->getSessionMaxLifeTime())) {
			$this->setSessionMaxLifeTime($sessionMaxTime);
		}

		# Ini set cookie life time
		if(null !== ($cookieLifeTime = $conf->getCookieLifeTime())) {
			$this->setCookieLifeTime($cookieLifeTime);
		}

		# Ini set cookie path
		if(null !== ($cookiePath = $conf->getCookiePath())) {
			$this->setCookiePath($cookiePath);
		}

		# Ini set cookie secure
		if(null !== ($cookieSecure = $conf->getCookieSecure())) {
			$this->setCookieSecure($cookieSecure);
		}

		# Ini set cookie httponly
		if(null !== ($cookieHttpOnly = $conf->getCookieHttpOnly())) {
			$this->setCookieHttpOnly($cookieHttpOnly);
		}

		# Start session with verification
		if($conf->isAutoStartSession()) {
			$this->startSession();
		}

		# TimeStamp
		$this->date = $conf->getSessionDate();

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
		# Already
		if($this->isActive()) { return $this; }

		# Start
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
	 * SET SESSION DOMAIN
	 *
	 * @param string $domain
	 * @return $this
	 */
	public function setSessionDomain(string $domain): Session
	{
		ini_set('session.session_domain', $domain);
		return $this;
	}

	/**
	 * SET COOKIE DOMAIN
	 *
	 * @param string $sCookieDomain
	 * @return $this
	 */
	public function setCookieDomain(string $domain): Session
	{
		ini_set('session.cookie_domain', $domain);
		return $this;
	}

	/**
	 * SET SESSION PATH
	 *
	 * @param string $sSessionPath
	 * @return $this
	 */
	public function setSessionPath(string $path): Session
	{
		ini_set('session.save_path', $path);
		return $this;
	}

	/**
	 * SET COOKIE PATH
	 *
	 * @param string $path
	 * @return $this
	 */
	public function setCookiePath(string $path): Session
	{
		ini_set('session.cookie_path', $path);
		return $this;
	}

	/**
	 * SET SESSION COOKIE LIFE TIME
	 *
	 * @param int $seconds
	 * @return $this
	 */
	public function setCookieLifeTime(int $seconds): Session
	{
		ini_set('session.cookie_lifetime', $seconds);
		return $this;
	}

	/**
	 * SET SESSION COOKIE SECURE
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function setCookieSecure(bool $state): Session
	{
		ini_set('session.cookie_secure', $state);
		return $this;
	}

	/**
	 * SET SESSION COOKIE HTTP ONLY
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function setCookieHttpOnly(bool $state): Session
	{
		ini_set('session.cookie_httponly', $state);
		return $this;
	}

	/**
	 * SET SESSION MAX LIFE TIME
	 *
	 * @param int $seconds
	 * @return $this
	 */
	public function setSessionMaxLifeTime(int $seconds): Session
	{
		ini_set('session.gc_maxlifetime', $seconds);
		return $this;
	}

	/**
	 * SET SESSION NAME
	 *
	 * @param string $sSessionName
	 * @return $this
	 */
	public function setSessionName(string $name): Session
	{
		ini_set('session.session_name', $name);
		return $this;
	}

	/**
	 * SET SESSION DATE
	 *
	 * @param DateTime $oDate
	 * @return $this
	 */
	public function setSessionDate(DateTime $date): Session
	{
		$this->date = $date;
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
		if($this->isActive()) { session_regenerate_id(); }
		return $this;
	}
}

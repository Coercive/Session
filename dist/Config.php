<?php
namespace Coercive\Security\Session;

use DateTime;

/**
 * @see \Coercive\Security\Session\Session
 */
class Config
{
	# INIT SET

	/** @var string Init session domain */
	private $sessionDomain = null;

	/** @var string Init cookie domain */
	private $cookieDomain = null;

	/** @var string Init cookie path */
	private $cookiePath = null;

	/** @var string Init session path */
	private $sessionPath = null;

	/** @var string Init session name */
	private $sessionName = null;

	/** @var DateTime Init session date */
	private $sessionDate = null;

	/** @var bool Init Cookie Secure */
	private $cookieSecure = false;

	/** @var bool Init Cookie Http Only */
	private $cookieHttpOnly = false;

	/** @var int Init Session Max Life Time */
	private $sessionMaxLifeTime = null;

	/** @var int Init Cookie Life Time */
	private $cookieLifeTime = null;

	/** @var int Init GC Probability */
	private $gcProbability = null;

	/** @var int Init GC Divisor */
	private $gcDivisor = null;

	/** @var bool Init Use Strict Mode */
	private $useStrictMode = null;

	# Options

	/** @var bool If the session will autostart or not */
	private $activate = true;

	/** @var bool Connection State */
	private $connectionState = false;

	/** @var string Connection DB Table */
	private $connectionTable = 'CONNECTION';

	/** @var string IP Connection DB Table */
	private $ipConnectionTable = 'IP_CONNECTION';

	/** @var string User Session Path */
	private $userSessionPath = 'user';

	/** @var string Redirect Session Path */
	private $redirectSessionPath = 'redirect';

	/**
	 * Config constructor.
	 *
	 * @return void
	 */
	public function __construct()
	{
		$this->sessionDate = new DateTime;
	}

# INIT ####################################################################################################################################

	/**
	 * SESSION DOMAIN
	 *
	 * Ini set session domain
	 *
	 * @param string $domain
	 * @return $this
	 */
	public function setSessionDomain(string $domain): Config
	{
		$this->sessionDomain = $domain;
		return $this;
	}

	/**
	 * @return string|null
	 */
	public function getSessionDomain()
	{
		return $this->sessionDomain;
	}

	/**
	 * COOKIE DOMAIN
	 *
	 * Ini set cookie domain
	 *
	 * @param string $domain
	 * @return $this
	 */
	public function setCookieDomain(string $domain): Config
	{
		$this->cookieDomain = $domain;
		return $this;
	}

	/**
	 * @return string|null
	 */
	public function getCookieDomain()
	{
		return $this->cookieDomain;
	}

	/**
	 * COOKIE DOMAIN
	 *
	 * Ini set cookie path
	 *
	 * @param string $path
	 * @return $this
	 */
	public function setCookiePath(string $path): Config
	{
		$this->cookiePath = $path;
		return $this;
	}

	/**
	 * @return string|null
	 */
	public function getCookiePath()
	{
		return $this->cookiePath;
	}

	/**
	 * SET COOKIE LIFE TIME
	 *
	 * Ini set cookie life time
	 *
	 * @param int $seconds
	 * @return $this
	 */
	public function setCookieLifeTime(int $seconds): Config
	{
		$this->cookieLifeTime = $seconds;
		return $this;
	}

	/**
	 * @return int|null
	 */
	public function getCookieLifeTime()
	{
		return $this->cookieLifeTime;
	}

	/**
	 * SET COOKIE SECURE
	 *
	 * Ini set cookie secure
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function setCookieSecure(bool $state): Config
	{
		$this->cookieSecure = $state;
		return $this;
	}

	/**
	 * @return bool|null
	 */
	public function getCookieSecure()
	{
		return $this->cookieSecure;
	}

	/**
	 * SET COOKIE HTTP ONLY
	 *
	 * Ini set cookie httponly
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function setCookieHttpOnly(bool $state): Config
	{
		$this->cookieHttpOnly = $state;
		return $this;
	}

	/**
	 * @return bool|null
	 */
	public function getCookieHttpOnly()
	{
		return $this->cookieHttpOnly;
	}

	/**
	 * SET USE STRICT MODE
	 *
	 * Ini set use strict mode
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function setUseStrictMode(bool $state): Config
	{
		$this->useStrictMode = $state;
		return $this;
	}

	/**
	 * @return bool|null
	 */
	public function getUseStrictMode()
	{
		return $this->useStrictMode;
	}

	/**
	 * SESSION PATH
	 *
	 * Ini set session save path
	 *
	 * @param string $path
	 * @return $this
	 */
	public function setSessionPath(string $path): Config
	{
		$this->sessionPath = $path;
		return $this;
	}

	/**
	 * @return string|null
	 */
	public function getSessionPath()
	{
		return $this->sessionPath;
	}

	/**
	 * SESSION NAME
	 *
	 * Ini set session name
	 *
	 * @param string $name
	 * @return $this
	 */
	public function setSessionName(string $name): Config
	{
		$this->sessionName = $name;
		return $this;
	}

	/**
	 * @return string|null
	 */
	public function getSessionName()
	{
		return $this->sessionName;
	}

	/**
	 * SESSION DATE
	 *
	 * Ini set session date
	 *
	 * @param DateTime $date
	 * @return $this
	 */
	public function setSessionDate(DateTime $date): Config
	{
		$this->sessionDate = $date;
		return $this;
	}

	/**
	 * @return DateTime
	 */
	public function getSessionDate(): DateTime
	{
		return $this->sessionDate;
	}

	/**
	 * SET SESSION MAX LIFE TIME
	 *
	 * @param int $seconds
	 * @return $this
	 */
	public function setSessionMaxLifeTime(int $seconds): Config
	{
		$this->sessionMaxLifeTime = $seconds;
		return $this;
	}

	/**
	 * @return int|null
	 */
	public function getSessionMaxLifeTime()
	{
		return $this->sessionMaxLifeTime;
	}

	/**
	 * SET GC PROBABILITY
	 *
	 * @param int $percent
	 * @return $this
	 */
	public function setGcProbability(int $percent): Config
	{
		$this->gcProbability = $percent;
		return $this;
	}

	/**
	 * @return int|null
	 */
	public function getGcProbability()
	{
		return $this->gcProbability;
	}

	/**
	 * SET GC PROBABILITY
	 *
	 * @param int $percent
	 * @return $this
	 */
	public function setGcDivisor(int $percent): Config
	{
		$this->gcDivisor = $percent;
		return $this;
	}

	/**
	 * @return int|null
	 */
	public function getGcDivisor()
	{
		return $this->gcDivisor;
	}

# OPTIONS #################################################################################################################################

	/**
	 * AUTO START SESSION
	 *
	 * The session objet will init session if not already active
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function setAutoStartSession(bool $state): Config
	{
		$this->activate = $state;
		return $this;
	}

	/**
	 * @return bool
	 */
	public function isAutoStartSession(): bool
	{
		return $this->activate;
	}

	/**
	 * SET CONNECTION STATE
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function setConnection(bool $state): Config
	{
		$this->connectionState = $state;
		return $this;
	}

	/**
	 * ENABLE CONNECTION
	 *
	 * @return $this
	 */
	public function enableConnection(): Config
	{
		$this->connectionState = true;
		return $this;
	}

	/**
	 * DISABLE CONNECTION
	 *
	 * @return $this
	 */
	public function disableConnection(): Config
	{
		$this->connectionState = false;
		return $this;
	}

	/**
	 * @return bool
	 */
	public function getConnectionState(): bool
	{
		return $this->connectionState;
	}

	/**
	 * SET CONNECTION TABLE
	 *
	 * @param string $name
	 * @return $this
	 */
	public function setConnectionTable(string $name): Config
	{
		$this->connectionTable = $name;
		return $this;
	}

	/**
	 * @return string
	 */
	public function getConnectionTable(): string
	{
		return $this->connectionTable;
	}

	/**
	 * SET IP CONNECTION TABLE
	 *
	 * @param string $name
	 * @return $this
	 */
	public function setIpConnectionTable(string $name): Config
	{
		$this->ipConnectionTable = $name;
		return $this;
	}

	/**
	 * @return string
	 */
	public function getIpConnectionTable(): string
	{
		return $this->ipConnectionTable;
	}

	/**
	 * SET USER SESSION PATH
	 *
	 * @param string $path
	 * @return $this
	 */
	public function setUserSessionPath(string $path): Config
	{
		$this->userSessionPath = $path;
		return $this;
	}

	/**
	 * @return string
	 */
	public function getUserSessionPath(): string
	{
		return $this->userSessionPath;
	}

	/**
	 * SET REDIRECT SESSION PATH
	 *
	 * @param string $path
	 * @return $this
	 */
	public function setRedirectSessionPath(string $path): Config
	{
		$this->redirectSessionPath = $path;
		return $this;
	}

	/**
	 * @return string
	 */
	public function getRedirectSessionPath(): string
	{
		return $this->redirectSessionPath;
	}
}

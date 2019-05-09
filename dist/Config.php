<?php
namespace Coercive\Security\Session;

use DateTime;

/**
 * @see \Coercive\Security\Session\Session
 */
class Config
{
	# Ini set

	/** @var array List of session ini set */
	private $ini = [];

	/** @var DateTime Init session date */
	private $date = null;

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
		$this->date = new DateTime;
	}

	/**
	 * Options for iniset
	 *
	 * @return array
	 */
	public function getIni()
	{
		return $this->ini;
	}

# INIT ####################################################################################################################################

	/**
	 * Session save handler
	 *
	 * @param string $handler
	 * @return $this
	 */
	public function setSaveHandler(string $handler): Config
	{
		$this->ini['session.save_handler'] = $handler;
		return $this;
	}

	/**
	 * Session save path
	 *
	 * @param string $domain
	 * @return $this
	 */
	public function setSavePath(string $domain): Config
	{
		$this->ini['session.save_path'] = $domain;
		return $this;
	}

	/**
	 * Session name
	 *
	 * @param string $name
	 * @return $this
	 */
	public function setName(string $name): Config
	{
		$this->ini['session.name'] = $name;
		return $this;
	}

	/**
	 * Session auto start
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function setAutoStart(bool $state): Config
	{
		$this->ini['session.auto_start'] = $state;
		return $this;
	}

	/**
	 * Session serialize handler
	 *
	 * @param string $handler
	 * @return $this
	 */
	public function setSerializeHandler(string $handler): Config
	{
		$this->ini['session.serialize_handler'] = $handler;
		return $this;
	}

	/**
	 * Session gc probability
	 *
	 * @param int $percent
	 * @return $this
	 */
	public function setGcProbability(int $percent): Config
	{
		$this->ini['session.gc_probability'] = $percent;
		return $this;
	}

	/**
	 * Session gc divisor
	 *
	 * @param int $percent
	 * @return $this
	 */
	public function setGcDivisor(int $percent): Config
	{
		$this->ini['session.gc_divisor'] = $percent;
		return $this;
	}

	/**
	 * Session gc max life time
	 *
	 * @param int $seconds
	 * @return $this
	 */
	public function setGcMaxlifetime(int $seconds): Config
	{
		$this->ini['session.gc_maxlifetime'] = $seconds;
		return $this;
	}

	/**
	 * Session referer check
	 *
	 * @param string $url
	 * @return $this
	 */
	public function setRefererCheck(string $url): Config
	{
		$this->ini['session.referer_check'] = $url;
		return $this;
	}

	/**
	 * Session entropy file
	 *
	 * @param string $path
	 * @return $this
	 */
	public function setEntropyFile(string $path): Config
	{
		$this->ini['session.entropy_file'] = $path;
		return $this;
	}

	/**
	 * Session entropy length
	 *
	 * @param int $bytes
	 * @return $this
	 */
	public function setEntropyLength(int $bytes): Config
	{
		$this->ini['session.entropy_length'] = $bytes;
		return $this;
	}

	/**
	 * Session use strict mode
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function setUseStrictMode(bool $state): Config
	{
		$this->ini['session.use_strict_mode'] = $state;
		return $this;
	}

	/**
	 * Session use cookies
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function setUseCookies(bool $state): Config
	{
		$this->ini['session.use_cookies'] = $state;
		return $this;
	}

	/**
	 * Session use only cookies
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function setUseOnlyCookies(bool $state): Config
	{
		$this->ini['session.use_only_cookies'] = $state;
		return $this;
	}

	/**
	 * Session cookie lifetime
	 *
	 * @param int $seconds
	 * @return $this
	 */
	public function setCookieLifetime (int $seconds): Config
	{
		$this->ini['session.cookie_lifetime'] = $seconds;
		return $this;
	}

	/**
	 * Session cookie path
	 *
	 * @param string $path
	 * @return $this
	 */
	public function setCookiePath(string $path): Config
	{
		$this->ini['session.cookie_path'] = $path;
		return $this;
	}

	/**
	 * Session cookie domain
	 *
	 * @param string $domain
	 * @return $this
	 */
	public function setCookieDomain(string $domain): Config
	{
		$this->ini['session.cookie_domain'] = $domain;
		return $this;
	}

	/**
	 * Session cookie secure
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function setCookieSecure(bool $state): Config
	{
		$this->ini['session.cookie_secure'] = $state;
		return $this;
	}

	/**
	 * Session cookie httponly
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function setCookieHttponly(bool $state): Config
	{
		$this->ini['session.cookie_httponly'] = $state;
		return $this;
	}

	/**
	 * Session cookie samesite
	 *
	 * @param string $site
	 * @return $this
	 */
	public function setCookieSamesite(string $site): Config
	{
		$this->ini['session.cookie_samesite'] = $site;
		return $this;
	}

	/**
	 * Session cache limiter
	 *
	 * @param string $method
	 * @return $this
	 */
	public function setCacheLimiter(string $method): Config
	{
		$this->ini['session.cache_limiter'] = $method;
		return $this;
	}

	/**
	 * Session cache expire
	 *
	 * @param int $minutes
	 * @return $this
	 */
	public function setCacheExpire(int $minutes): Config
	{
		$this->ini['session.cache_expire'] = $minutes;
		return $this;
	}

	/**
	 * Session use trans sid
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function setUseTransSid(bool $state): Config
	{
		$this->ini['session.use_trans_sid'] = $state;
		return $this;
	}

	/**
	 * Session use trans sid
	 *
	 * @param string $tags
	 * @return $this
	 */
	public function setTransSidTags(string $tags): Config
	{
		$this->ini['session.trans_sid_tags'] = $tags;
		return $this;
	}

	/**
	 * Session trans sid hosts
	 *
	 * @param string $hosts
	 * @return $this
	 */
	public function setTransSidHosts(string $hosts): Config
	{
		$this->ini['session.trans_sid_hosts'] = $hosts;
		return $this;
	}

	/**
	 * Session bug compat 42
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function setBugCompat42(bool $state): Config
	{
		$this->ini['session.bug_compat_42'] = $state;
		return $this;
	}

	/**
	 * Session bug compat warn
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function setBugCompatWarn(bool $state): Config
	{
		$this->ini['session.bug_compat_warn'] = $state;
		return $this;
	}

	/**
	 * Session sid length
	 *
	 * @param int $length
	 * @return $this
	 */
	public function setSidLength(int $length): Config
	{
		$this->ini['session.sid_length'] = $length;
		return $this;
	}

	/**
	 * Session sid bits per character
	 *
	 * @param int $length
	 * @return $this
	 */
	public function setSidBitsPerCharacter(int $length): Config
	{
		$this->ini['session.sid_bits_per_character'] = $length;
		return $this;
	}

	/**
	 * Session hash function
	 *
	 * @param string $algorithm
	 * @return $this
	 */
	public function setHashFunction(string $algorithm): Config
	{
		$this->ini['session.hash_function'] = $algorithm;
		return $this;
	}

	/**
	 * Session hash bits per character
	 *
	 * @param int $bits
	 * @return $this
	 */
	public function setHashBitsPerCharacter (int $bits): Config
	{
		$this->ini['session.hash_bits_per_character'] = $bits;
		return $this;
	}

	/**
	 * Session upload progress enabled
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function setUploadProgressEnabled(bool $state): Config
	{
		$this->ini['session.upload_progress.enabled'] = $state;
		return $this;
	}

	/**
	 * Session upload progress cleanup
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function setUploadProgressCleanup(bool $state): Config
	{
		$this->ini['session.upload_progress.cleanup'] = $state;
		return $this;
	}

	/**
	 * Session upload progress prefix
	 *
	 * @param string $prefix
	 * @return $this
	 */
	public function setUploadProgressPrefix(string $prefix): Config
	{
		$this->ini['session.upload_progress.prefix'] = $prefix;
		return $this;
	}

	/**
	 * Session upload progress name
	 *
	 * @param string $name
	 * @return $this
	 */
	public function setUploadProgressName(string $name): Config
	{
		$this->ini['session.upload_progress.name'] = $name;
		return $this;
	}

	/**
	 * Session upload progress freq
	 *
	 * @param string $freq
	 * @return $this
	 */
	public function setUploadProgressFreq(string $freq): Config
	{
		$this->ini['session.upload_progress.freq'] = $freq;
		return $this;
	}

	/**
	 * Session upload progress min_freq
	 *
	 * @param int $seconds
	 * @return $this
	 */
	public function setUploadProgressMinFreq(int $seconds): Config
	{
		$this->ini['session.upload_progress.min_freq'] = $seconds;
		return $this;
	}

	/**
	 * Session lazy write
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function setLazyWrite(bool $state): Config
	{
		$this->ini['session.lazy_write'] = $state;
		return $this;
	}

# OPTIONS #################################################################################################################################

	/**
	 * DATE
	 *
	 * @param DateTime $date
	 * @return $this
	 */
	public function setDate(DateTime $date): Config
	{
		$this->date = $date;
		return $this;
	}

	/**
	 * DATE
	 *
	 * @return DateTime
	 */
	public function getDate(): DateTime
	{
		return $this->date;
	}

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

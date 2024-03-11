<?php
namespace Coercive\Security\Session;

/**
 * @see \Coercive\Security\Session\Session
 */
class User
{
	const
		CONNECTED_PATH = 'connected',
		LANGUAGE_PATH = 'language',
		TIME_PATH = 'time',
		TOKEN_PATH = 'token',
		LOGIN_PATH = 'login',
		ID_PATH = 'id',
		LEVEL_PATH = 'level',
		FROM_PATH = 'from',
		ORIGIN_PATH = 'origin',
		COLLECTIVE_SUBSCRIPTION_PATH = 'collective_subscription',
		COLLECTIVE_SUBSCRIPTION_BY_IP_PATH = 'collective_subscription_by_ip',
		COLLECTIVE_SUBSCRIPTION_BY_DOMAIN_PATH = 'collective_subscription_by_domain',
		COLLECTIVE_SUBSCRIPTION_BY_EMAIL_PATH = 'collective_subscription_by_email';

	private Session $session;

	/** @var string Session user path */
	private string $path;

	/**
	 * User constructor.
	 *
	 * @param Session $session
	 * @return void
	 */
	public function __construct(Session $session)
	{
		$this->session = $session;
		$this->path = $session->Config()->getUserSessionPath();
	}

	/**
	 * DELETE USER
	 *
	 * @return $this
	 */
	public function delete(): self
	{
		if($this->session->isActive()) {
			unset($_SESSION[$this->path]);
		}
		return $this;
	}

	/**
	 * IS CONNECTED STATE
	 *
	 * @return bool
	 */
	public function isConnected(): bool
	{
		return $this->session->isActive() && !empty($_SESSION[$this->path][self::CONNECTED_PATH]);
	}

	/**
	 * SET CONNECTED STATE
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function setConnectedState(bool $state): self
	{
		if($this->session->isActive()) {
			$_SESSION[$this->path][self::CONNECTED_PATH] = $state;
		}
		return $this;
	}

	/**
	 * Is connection active with collective subscription
	 *
	 * @return bool
	 */
	public function isCollectiveSubscription(): bool
	{
		if(!$this->session->isActive() || empty($_SESSION[$this->path][self::COLLECTIVE_SUBSCRIPTION_PATH])) {
			return false;
		}
		return $this->isConnected();
	}

	/**
	 * @param bool $state
	 * @return $this
	 */
	public function setCollectiveSubscription(bool $state): self
	{
		if($this->session->isActive()) {
			$_SESSION[$this->path][self::COLLECTIVE_SUBSCRIPTION_PATH] = $state;
		}
		return $this;
	}

	/**
	 * The IP from collective subscription
	 *
	 * @return string
	 */
	public function getCollectiveSubscriptionIp(): string
	{
		if(!$this->session->isActive() || empty($_SESSION[$this->path][self::COLLECTIVE_SUBSCRIPTION_BY_IP_PATH])) {
			return false;
		}
		return (string) filter_var($_SESSION[$this->path][self::COLLECTIVE_SUBSCRIPTION_BY_IP_PATH], FILTER_VALIDATE_IP);
	}

	/**
	 * @param string $ip
	 * @return $this
	 */
	public function setCollectiveSubscriptionIp(string $ip): self
	{
		if($this->session->isActive()) {
			$_SESSION[$this->path][self::COLLECTIVE_SUBSCRIPTION_BY_IP_PATH] = (string) filter_var($ip, FILTER_VALIDATE_IP);
		}
		return $this;
	}

	/**
	 * The DOMAIN from collective subscription
	 *
	 * @return string
	 */
	public function getCollectiveSubscriptionDomain(): string
	{
		if(!$this->session->isActive() || empty($_SESSION[$this->path][self::COLLECTIVE_SUBSCRIPTION_BY_DOMAIN_PATH])) {
			return false;
		}
		return (string) filter_var($_SESSION[$this->path][self::COLLECTIVE_SUBSCRIPTION_BY_DOMAIN_PATH], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
	}

	/**
	 * @param string $domain
	 * @return $this
	 */
	public function setCollectiveSubscriptionDomain(string $domain): self
	{
		if($this->session->isActive()) {
			$_SESSION[$this->path][self::COLLECTIVE_SUBSCRIPTION_BY_DOMAIN_PATH] = (string) filter_var($domain, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		}
		return $this;
	}

	/**
	 * The EMAIL from collective subscription
	 *
	 * @return string
	 */
	public function getCollectiveSubscriptionEmail(): string
	{
		if(!$this->session->isActive() || empty($_SESSION[$this->path][self::COLLECTIVE_SUBSCRIPTION_BY_EMAIL_PATH])) {
			return false;
		}
		return (string) filter_var($_SESSION[$this->path][self::COLLECTIVE_SUBSCRIPTION_BY_EMAIL_PATH], FILTER_VALIDATE_EMAIL);
	}

	/**
	 * @param string $email
	 * @return $this
	 */
	public function setCollectiveSubscriptionEmail(string $email): self
	{
		if($this->session->isActive()) {
			$_SESSION[$this->path][self::COLLECTIVE_SUBSCRIPTION_BY_EMAIL_PATH] = (string) filter_var($email, FILTER_VALIDATE_EMAIL);
		}
		return $this;
	}

	/**
	 * GET USER ID
	 *
	 * @return int
	 */
	public function getId(): int
	{
		if(!$this->session->isActive() || empty($_SESSION[$this->path][self::ID_PATH])) {
			return 0;
		}
		return (int) $_SESSION[$this->path][self::ID_PATH];
	}

	/**
	 * SET USER ID
	 *
	 * @param int $id
	 * @return $this
	 */
	public function setId(int $id): self
	{
		if($this->session->isActive()) {
			$_SESSION[$this->path][self::ID_PATH] = $id;
		}
		return $this;
	}

	/**
	 * GET USER LOGIN
	 *
	 * @return string
	 */
	public function getLogin(): string
	{
		if(!$this->session->isActive() || empty($_SESSION[$this->path][self::LOGIN_PATH])) {
			return '';
		}
		return (string) filter_var($_SESSION[$this->path][self::LOGIN_PATH], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
	}

	/**
	 * SET USER LOGIN
	 *
	 * @param string $login
	 * @return $this
	 */
	public function setLogin(string $login): self
	{
		if($this->session->isActive()) {
			$_SESSION[$this->path][self::LOGIN_PATH] = (string) filter_var($login, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		}
		return $this;
	}

	/**
	 * GET USER TOKEN
	 *
	 * @return string
	 */
	public function getToken(): string
	{
		if(!$this->session->isActive() || empty($_SESSION[$this->path][self::TOKEN_PATH])) {
			return '';
		}
		return (string) filter_var($_SESSION[$this->path][self::TOKEN_PATH], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
	}

	/**
	 * SET USER TOKEN
	 *
	 * @param string $token
	 * @return $this
	 */
	public function setToken(string $token): self
	{
		if($this->session->isActive()) {
			$_SESSION[$this->path][self::TOKEN_PATH] = (string) filter_var($token, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		}
		return $this;
	}

	/**
	 * GET USER TIME
	 *
	 * @return int
	 */
	public function getTime(): int
	{
		if(!$this->session->isActive() || empty($_SESSION[$this->path][self::TIME_PATH])) {
			return 0;
		}
		return (int) $_SESSION[$this->path][self::TIME_PATH];
	}

	/**
	 * SET USER TIME
	 *
	 * @param int $time
	 * @return $this
	 */
	public function setTime(int $time): self
	{
		if($this->session->isActive()) {
			$_SESSION[$this->path][self::TIME_PATH] = $time;
		}
		return $this;
	}

	/**
	 * GET USER LANGUAGE
	 *
	 * @return string
	 */
	public function getLanguage(): string
	{
		if(!$this->session->isActive() || empty($_SESSION[$this->path][self::LANGUAGE_PATH])) {
			return '';
		}
		return (string) filter_var($_SESSION[$this->path][self::LANGUAGE_PATH], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
	}

	/**
	 * SET USER LANGUAGE
	 *
	 * @param string $lang
	 * @return $this
	 */
	public function setLanguage(string $lang): self
	{
		if($this->session->isActive()) {
			$_SESSION[$this->path][self::LANGUAGE_PATH] = (string) filter_var($lang, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		}
		return $this;
	}

	/**
	 * GET USER LEVEL
	 *
	 * @return string
	 */
	public function getLevel(): string
	{
		if(!$this->session->isActive() || empty($_SESSION[$this->path][self::LEVEL_PATH])) {
			return '';
		}
		return (string) filter_var($_SESSION[$this->path][self::LEVEL_PATH], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
	}

	/**
	 * SET USER LEVEL
	 *
	 * @param string $lvl
	 * @return $this
	 */
	public function setLevel(string $lvl): self
	{
		if($this->session->isActive()) {
			$_SESSION[$this->path][self::LEVEL_PATH] = (string) filter_var($lvl, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		}
		return $this;
	}

	/**
	 * GET USER FROM
	 *
	 * @return string
	 */
	public function getFrom(): string
	{
		if(!$this->session->isActive() || empty($_SESSION[$this->path][self::FROM_PATH])) {
			return '';
		}
		return (string) filter_var($_SESSION[$this->path][self::FROM_PATH], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
	}

	/**
	 * SET USER FROM
	 *
	 * @param string $from
	 * @return $this
	 */
	public function setFrom(string $from): self
	{
		if($this->session->isActive()) {
			$_SESSION[$this->path][self::FROM_PATH] = (string) filter_var($from, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		}
		return $this;
	}

	/**
	 * GET USER ORIGIN
	 *
	 * @return string
	 */
	public function getOrigin(): string
	{
		if(!$this->session->isActive() || empty($_SESSION[$this->path][self::ORIGIN_PATH])) {
			return '';
		}
		return (string) filter_var($_SESSION[$this->path][self::ORIGIN_PATH], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
	}

	/**
	 * SET USER ORIGIN
	 *
	 * @param string $origin
	 * @return $this
	 */
	public function setOrigin(string $origin): self
	{
		if($this->session->isActive()) {
			$_SESSION[$this->path][self::ORIGIN_PATH] = (string) filter_var($origin, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		}
		return $this;
	}
}
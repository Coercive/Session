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
		ID_PATH = 'id';

	/** @var Session */
	private $session = null;

	/** @var string Session user path */
	private $path = '';

	/**
	 * User constructor.
	 *
	 * @param Session $session
	 */
	public function __construct(Session $session)
	{
		$this->session = $session;
		$this->path = $session->Config()->getUserSessionPath();
	}

	/**
	 * IS CONNECTED STATE
	 *
	 * @return bool
	 */
	public function isConnected(): bool
	{
		# No datas
		if(!$this->session->isActive() || empty($_SESSION[$this->path][self::CONNECTED_PATH])) { return false; }

		# Retrieve
		return (bool) $_SESSION[$this->path][self::CONNECTED_PATH];
	}

	/**
	 * SET CONNECTED STATE
	 *
	 * @param bool $bState
	 * @return $this
	 */
	public function setConnectedState(bool $state): User
	{
		# Set
		if($this->session->isActive()) {
			$_SESSION[$this->path][self::CONNECTED_PATH] = (bool) $state;
		}

		# Maintain chainability
		return $this;
	}

	/**
	 * GET USER ID
	 *
	 * @return int
	 */
	public function getId(): int
	{
		# No datas
		if(!$this->session->isActive() || empty($_SESSION[$this->path][self::ID_PATH])) { return 0; }

		# Retrieve
		return (int) filter_var($_SESSION[$this->path][self::ID_PATH], FILTER_VALIDATE_INT);
	}

	/**
	 * SET USER ID
	 *
	 * @param int $id
	 * @return $this
	 */
	public function setId(int $id): User
	{
		# Set
		if($this->session->isActive()) {
			$_SESSION[$this->path][self::ID_PATH] = filter_var($id, FILTER_VALIDATE_INT) ?: 0;
		}

		# Maintain chainability
		return $this;
	}

	/**
	 * GET USER LOGIN
	 *
	 * @return string
	 */
	public function getLogin(): string
	{
		# No datas
		if(!$this->session->isActive() || empty($_SESSION[$this->path][self::LOGIN_PATH])) { return ''; }

		# Retrieve
		return (string) strtolower(filter_var($_SESSION[$this->path][self::LOGIN_PATH], FILTER_VALIDATE_EMAIL));
	}

	/**
	 * SET USER LOGIN
	 *
	 * @param string $email
	 * @return $this
	 */
	public function setLogin(string $email): User
	{
		# Set
		if($this->session->isActive()) {
			$_SESSION[$this->path][self::LOGIN_PATH] = strtolower(filter_var($email, FILTER_VALIDATE_EMAIL) ?: '');
		}

		# Maintain chainability
		return $this;
	}

	/**
	 * GET USER TOKEN
	 *
	 * @return string
	 */
	public function getToken(): string
	{
		# No datas
		if(!$this->session->isActive() || empty($_SESSION[$this->path][self::TOKEN_PATH])) { return ''; }

		# Retrieve
		return (string) filter_var($_SESSION[$this->path][self::TOKEN_PATH], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
	}

	/**
	 * SET USER TOKEN
	 *
	 * @param string $token
	 * @return $this
	 */
	public function setToken(string $token): User
	{
		# Set
		if($this->session->isActive()) {
			$_SESSION[$this->path][self::TOKEN_PATH] = filter_var($token, FILTER_SANITIZE_FULL_SPECIAL_CHARS) ?: '';
		}

		# Maintain chainability
		return $this;
	}

	/**
	 * GET USER TIME
	 *
	 * @return int
	 */
	public function getTime(): int
	{
		# No datas
		if(!$this->session->isActive() || empty($_SESSION[$this->path][self::TIME_PATH])) { return 0; }

		# Retrieve
		return (int) filter_var($_SESSION[$this->path][self::TIME_PATH], FILTER_VALIDATE_INT);
	}

	/**
	 * SET USER TIME
	 *
	 * @param int $time
	 * @return $this
	 */
	public function setTime(int $time): User
	{
		# Set
		if($this->session->isActive()) {
			$_SESSION[$this->path][self::TIME_PATH] = filter_var($time, FILTER_VALIDATE_INT) ?: 0;
		}

		# Maintain chainability
		return $this;
	}

	/**
	 * GET USER LANGUAGE
	 *
	 * @return string
	 */
	public function getLanguage(): string
	{
		# No datas
		if(!$this->session->isActive() || empty($_SESSION[$this->path][self::LANGUAGE_PATH])) { return ''; }

		# Retrieve
		return (string) filter_var($_SESSION[$this->path][self::LANGUAGE_PATH], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
	}

	/**
	 * SET USER LANGUAGE
	 *
	 * @param string $lang
	 * @return $this
	 */
	public function setLanguage(string $lang): User
	{
		# Set
		if($this->session->isActive()) {
			$_SESSION[$this->path][self::LANGUAGE_PATH] = filter_var($lang, FILTER_SANITIZE_FULL_SPECIAL_CHARS) ?: '';
		}

		# Maintain chainability
		return $this;
	}

	/**
	 * DELETE USER
	 *
	 * @return $this
	 */
	public function delete(): User
	{
		# Delete
		if($this->session->isActive()) {
			unset($_SESSION[$this->path]);
		}

		# Maintain chainability
		return $this;
	}
}

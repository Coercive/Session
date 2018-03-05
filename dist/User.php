<?php
namespace Coercive\Security\Session;

/**
 * @see \Coercive\Security\Session\Session
 */
class User
{
	const
		CONNECTED_PATH = 'connected',
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
	 * @param int $iId
	 * @return $this
	 */
	public function setId(int $id): User
	{
		# Set
		if($this->session->isActive()) {
			$_SESSION[$this->path][self::ID_PATH] = filter_var($iId, FILTER_VALIDATE_INT) ?: 0;
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
	 * @param string $sEmail
	 * @return $this
	 */
	public function setLogin(string $email): User
	{
		# Set
		if($this->session->isActive()) {
			$_SESSION[$this->path][self::LOGIN_PATH] = strtolower(filter_var($sEmail, FILTER_VALIDATE_EMAIL) ?: '');
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
			$_SESSION[$this->path][self::LOGIN_PATH] = filter_var($token, FILTER_SANITIZE_FULL_SPECIAL_CHARS) ?: '';
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
			unset($_SESSION[$this->path][self::LOGIN_PATH], $_SESSION[$this->path][self::ID_PATH], $_SESSION[$this->path][self::CONNECTED_PATH]);
		}

		# Maintain chainability
		return $this;
	}
}

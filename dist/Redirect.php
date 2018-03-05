<?php
namespace Coercive\Security\Session;

/**
 * @see Coercive\Security\Session\Session
 */
class Redirect
{
	/** @var Session */
	private $session = null;

	/** @var string Session redirect path */
	private $path = '';

	/**
	 * Redirect constructor.
	 *
	 * @param Session $session
	 */
	public function __construct(Session $session)
	{
		$this->session = $session;
		$this->path = $session->Config()->getRedirectSessionPath();
	}

	/**
	 * GETTER REDIRECT LINK
	 *
	 * @return string
	 */
	public function get(): string
	{
		# No datas
		if(!$this->session->isActive() || empty($_SESSION[$this->path])) { return '/'; }

		# Retrieve
		return (string) filter_var($_SESSION[$this->path], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
	}

	/**
	 * SETTER REDIRECT LINK
	 *
	 * @param string $link
	 * @return $this
	 */
	public function set(string $link): Redirect
	{
		# Set
		if($this->session->isActive()) {
			$_SESSION[$this->path] = (string) filter_var($link, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		}

		# Maintain chainability
		return $this;
	}

	/**
	 * DELETE REDIRECT LINK
	 *
	 * @return $this
	 */
	public function delete(): Redirect
	{
		# Delete
		if($this->session->isActive()) {
			unset($_SESSION[$this->path]);
		}

		# Maintain chainability
		return $this;
	}
}

<?php
namespace Coercive\Security\Session;

/**
 * @see \Coercive\Security\Session\Session
 */
class Redirect
{
	private Session $session;

	/** @var string Session redirect path */
	private string $path;

	/**
	 * Redirect constructor.
	 *
	 * @param Session $session
	 * @return void
	 */
	public function __construct(Session $session)
	{
		$this->session = $session;
		$this->path = $session->Config()->getRedirectSessionPath();
	}

	/**
	 * DELETE REDIRECT LINK
	 *
	 * @return $this
	 */
	public function delete(): Redirect
	{
		if($this->session->isActive()) {
			unset($_SESSION[$this->path]);
		}
		return $this;
	}

	/**
	 * HAS REDIRECT LINK
	 *
	 * @return bool
	 */
	public function has(): bool
	{
		return $this->session->isActive() && !empty($_SESSION[$this->path]);
	}

	/**
	 * GETTER REDIRECT LINK
	 *
	 * @return string
	 */
	public function get(): string
	{
		if(!$this->has()) {
			return '/';
		}
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
		if($this->session->isActive()) {
			$_SESSION[$this->path] = (string) filter_var($link, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		}
		return $this;
	}
}
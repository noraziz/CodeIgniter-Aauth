<?php

namespace noraziz\ci4aauth;

/**
 * This is Aauth library for Codeigniter 4.x, maintaned by Nor Aziz <tonoraziz@gmail.com>.
 * 
 * 
 * -- Original Descriptions --
 * Aauth is a User Authorization Library for CodeIgniter 2.x, which aims to make
 * easy some essential jobs such as login, permissions and access operations.
 * Despite ease of use, it has also very advanced features like private messages,
 * groupping, access management, public access etc..
 *
 * @author		Emre Akay <emreakayfb@hotmail.com>
 * @contributor Jacob Tomlinson
 * @contributor Tim Swagger (Renowne, LLC) <tim@renowne.com>
 * @contributor Raphael Jackstadt <info@rejack.de>
 *
 * @copyright 2014-2018 Emre Akay
 *
 * @version 2.5.15
 *
 * @license LGPL
 * @license http://opensource.org/licenses/LGPL-3.0 Lesser GNU Public License
 *
 * The latest version of Aauth can be obtained from:
 * https://github.com/emreakay/CodeIgniter-Aauth
 *
 * @todo separate (on some level) the unvalidated users from the "banned" users
 */

use CodeIgniter\Cookie\Cookie;
use Config\Encryption;
use DateTime;
use Vectorface\GoogleAuthenticator;
use google\recaptcha;
use noraziz\ci4aauth\Config\AauthConfig as AauthCfg;
use noraziz\ci4aauth\Models\AauthModel;

class Aauth
{

	/**
	 * Variable for loading the config array into
	 * @access public
	 * @var array
	 */
	public $config_vars;
	
	private $session;
	private $cookie;
	private $request;
	private $aaModel;

	/**
	 * Array to store error messages
	 * @access public
	 * @var array
	 */
	public $errors = array();

	/**
	 * Array to store info messages
	 * @access public
	 * @var array
	 */
	public $infos = array();

	/**
	 * Local temporary storage for current flash errors
	 *
	 * Used to update current flash data list since flash data is only available on the next page refresh
	 * @access public
	 * var array
	 */
	public $flash_errors = array();

	/**
	 * Local temporary storage for current flash infos
	 *
	 * Used to update current flash data list since flash data is only available on the next page refresh
	 * @access public
	 * var array
	 */
	public $flash_infos = array();

	/**
	 * Array to cache permission-ids.
	 * @access private
	 * @var array
	 */
	 private $cache_perm_id;

	/**
	 * Array to cache group-ids.
	 * @access private
	 * @var array
	 */
	 private $cache_group_id;


	/**
	* Constructor
	*
	*/
    public function __construct(?AauthCfg $config = null)
    {
        // If no configuration was supplied then load one
        $this->config_vars = $config ?? config('AauthConfig');
		$this->aaModel = new \noraziz\ci4aauth\Models\AauthModel();
        
        // Sessions
        $this->session = \Config\Services::session();
        $this->errors  = $this->session->getFlashdata('errors') ?: array();
		$this->infos   = $this->session->getFlashdata('infos') ?: array();
		
		// Other Services
		$this->request= \Config\Services::request();
		
		// Initialize Variables
		$this->cache_perm_id  = array();
		$this->cache_group_id = array();
		
		// Pre-Cache IDs
		$this->precache_perms();
		$this->precache_groups();
    }
	
	/**
	 * precache_perms() caches all permission IDs for later use.
	 */
	private function precache_perms()
	{
		foreach ($this->aaModel->get_precache_perms() as $row) {
			$key				= str_replace(' ', '', trim(strtolower($row->name)));
			$this->cache_perm_id[$key]	= $row->id;
		}
	}
	
	/**
	 * precache_groups() caches all group IDs for later use.
	 */
	private function precache_groups()
	{
		foreach ($this->aaModel->get_precache_groups() as $row) {
			$key				= str_replace(' ', '', trim(strtolower($row->name)));
			$this->cache_group_id[$key]	= $row->id;
		}
	}
	
	
	
	
	########################
	# Login Functions
	########################

	/**
	 * Login user
	 * Check provided details against the database. Add items to error array on fail, create session if success
	 * @param string $email
	 * @param string $pass
	 * @param bool $remember
	 * @return bool Indicates successful login.
	 */
	public function login($identifier, $pass, $remember = false, $totp_code = null)
	{
		// Remove cookies first
		$this->cookie = new Cookie('user', '',
			[
			'expires'  => new DateTime('-1 hours'),
			'path'     => '/'
			]
		);
		
		if ($this->config_vars->ddos_protection && ! $this->update_login_attempts()) {

			$this->error( lang('AauthCore.aauth_error_login_attempts_exceeded') );
			return false;
		}
		
		if($this->config_vars->ddos_protection && $this->config_vars->recaptcha_active && $this->get_login_attempts() > $this->config_vars->recaptcha_login_attempts)
		{
			$recaptcha = new \ReCaptcha\ReCaptcha( $this->config_vars->recaptcha_secret );
			$resp = $recaptcha->verify( $this->request->getPost('g-recaptcha-response'), $this->request->getServer('REMOTE_ADDR') );

			if( ! $resp->isSuccess() ){
				$this->error( lang('AauthCore.aauth_error_recaptcha_not_correct') );
				return false;
			}
		}
		
 		if( $this->config_vars->login_with_name == true){

			if( !$identifier OR strlen($pass) < $this->config_vars->char_min OR strlen($pass) > $this->config_vars->char_max )
			{
				$this->error( lang('AauthCore.aauth_error_login_failed_name') );
				return false;
			}
			$db_identifier = 'username';
 		}else{
			if( !filter_var($identifier, FILTER_VALIDATE_EMAIL) OR strlen($pass) < $this->config_vars->char_min OR strlen($pass) > $this->config_vars->char_max )
			{
				$this->error( lang('AauthCore.aauth_error_login_failed_email') );
				return false;
			}
			$db_identifier = 'email';
 		}

		// if user is not verified
		$dtUsrRow = $this->aaModel->do_login_verified($db_identifier, $identifier, true);

		if ( !isset($dtUsrRow) ) {
			$this->error( lang('AauthCore.aauth_error_account_not_verified') );
			return false;
		}

		// to find user id, create sessions and cookies
		$dtUsrRow_1 = $this->aaModel->do_login_verified($db_identifier, $identifier, false);

		if( !isset($dtUsrRow_1) ){
			$this->error( lang('AauthCore.aauth_error_no_user') );
			return false;
		}
		
		
		if($this->config_vars->totp_active == true AND $this->config_vars->totp_only_on_ip_change == false AND $this->config_vars->totp_two_step_login_active == true){
			if($this->config_vars->totp_two_step_login_active == true){
				$this->session->set('totp_required', true);
			}

			$dtUsrRow_2 = $this->aaModel->do_login_verified($db_identifier, $identifier, false);
			if ( isset($dtUsrRow_2) AND !$totp_code) {
				$this->error( lang('AauthCore.aauth_error_totp_code_required') );
				return false;
			}else if ( isset($dtUsrRow_2)) {
				$totp_secret = $dtUsrRow_2->totp_secret;
				
				if(!empty($totp_secret)){
					$ga = new GoogleAuthenticator();
					$checkResult = $ga->verifyCode($totp_secret, $totp_code, 0);
					if (!$checkResult) {
						$this->error( lang('AauthCore.aauth_error_totp_code_invalid') );
						return false;
					}
				}
			}
	 	}

	 	if($this->config_vars->totp_active == true AND $this->config_vars->totp_only_on_ip_change == true){
			$dtUsrRow_3  = $this->aaModel->do_login_verified($db_identifier, $identifier, false);
			$totp_secret = $dtUsrRow_3->totp_secret;
			$ip_address  = $dtUsrRow_3->ip_address;
			$current_ip_address = $request->getIPAddress();

			if ($query->num_rows() > 0 AND !$totp_code) {
				if($ip_address != $current_ip_address ){
					if($this->config_vars->totp_two_step_login_active == false){
						$this->error( lang('AauthCore.aauth_error_totp_code_required') );
						return false;
					} else if($this->config_vars->totp_two_step_login_active == true){
						$this->CI->session->set_userdata('totp_required', true);
					}
				}
			}else {
				if(!empty($totp_secret)){
					if($ip_address != $current_ip_address ){
						$ga = new GoogleAuthenticator();
						$checkResult = $ga->verifyCode($totp_secret, $totp_code, 0);
						if (!$checkResult) {
							$this->error( lang('AauthCore.aauth_error_totp_code_invalid') );
							return false;
						}
					}
				}
			}
	 	}

		$dtUsrRow_4 = $this->aaModel->do_login_verified($db_identifier, $identifier, false, 0);

		// if email and pass matches and not banned
		if ( isset($dtUsrRow_4) ) {
			$password = ($this->config_vars->use_password_hash ? $pass : $this->aaModel->hash_password($pass, $dtUsrRow_4->id));

			if ($this->verify_password($password, $dtUsrRow_4->pass)) {
				// If email and pass matches
				// create session
				$data = array(
					'id' => $dtUsrRow_4->id,
					'username' => $dtUsrRow_4->username,
					'email' => $dtUsrRow_4->email,
					'loggedin' => true
				);
				$this->session->set($data);

				if ($remember){
					helper('text');
					$expire = $this->config_vars->remember;
					$today = date("Y-m-d");
					$remember_date = date("Y-m-d", strtotime($today . $expire) );
					$random_string = random_string('alnum', 16);
					$this->update_remember($dtUsrRow_4->id, $random_string, $remember_date );
					$cookie = array(
						'name'	 => 'user',
						'value'	 => $dtUsrRow_4->id . "-" . $random_string,
						'expire' => 99*999*999,
						'path'	 => '/',
					);
					
					helper('cookie');
					set_cookie($cookie);
				}

				// update last login
				$this->update_last_login($dtUsrRow_4->id);
				$this->update_activity();

				if($this->config_vars->remove_successful_attempts == true){
					$this->reset_login_attempts();
				}

				return true;
			}
		}
		// if not matches
		else {

			$this->error( lang('AauthCore.aauth_error_login_failed_all') );
			return false;
		}
	}

	/**
	 * Check user login
	 * Checks if user logged in, also checks remember.
	 * @return bool
	 */
	public function is_loggedin()
	{
		if ( $this->session->get('loggedin') ){
			return true;
		} else {
			helper('cookie');
			
			if( !get_cookie('user', true) ){
				return false;
			} else {
				$cookie = explode('-', get_cookie('user', true));
				if(!is_numeric( $cookie[0] ) OR strlen($cookie[1]) < 13 ){return false;}
				else{
					$dtUsrRow= $this->aaModel->do_login_fast($user_id);

					if ( !isset($dtUsrRow) ) {
						$this->update_remember($cookie[0]);
						return false;
					}else{

						if(strtotime($dtUsrRow->remember_time) > strtotime("now") ){
							$this->login_fast($cookie[0]);
							return true;
						}
						// if time is expired
						else {
							return false;
						}
					}
				}
			}
		}
		return false;
	}

	/**
	 * Controls if a logged or public user has permission
	 *
	 * If user does not have permission to access page, it stops script and gives
	 * error message, unless 'no_permission' value is set in config.  If 'no_permission' is
	 * set in config it redirects user to the set url and passes the 'no_access' error message.
	 * It also updates last activity every time function called.
	 *
	 * @param bool $perm_par If not given just control user logged in or not
	 */
	public function control( $perm_par = false )
	{
		if($this->session->get('totp_required')){
			$this->error( lang('AauthCore.aauth_error_totp_verification_required') );
			redirect($this->config_vars->totp_two_step_login_redirect);
		}

		$perm_id = $this->get_perm_id($perm_par);
		$this->update_activity();
		if($perm_par == false){
			if($this->is_loggedin()){
				return true;
			}else if(!$this->is_loggedin()){
				$this->error( lang('AauthCore.aauth_error_no_access') );
				if($this->config_vars->no_permission !== false){
					redirect($this->config_vars->no_permission);
				}
			}

		}else if ( ! $this->is_allowed($perm_id) ){
			if( $this->config_vars->no_permission ) {
				$this->error( lang('AauthCore.aauth_error_no_access') );
				if($this->config_vars->no_permission !== false){
					redirect($this->config_vars->no_permission);
				}
			}
			else {
				echo lang('AauthCore.aauth_error_no_access');
				die();
			}
		}
	}

	/**
	 * Logout user
	 * Destroys the CodeIgniter session and remove cookies to log out user.
	 * @return bool If session destroy successful
	 */
	public function logout()
	{
		$this->cookie = new Cookie('user', '',
			[
			'expires'  => new DateTime('-1 hours'),
			'path'     => '/'
			]
		);

		return $this->session->destroy();;
	}

	/**
	 * Fast login
	 * Login with just a user id
	 * @param int $user_id User id to log in
	 * @return bool TRUE if login successful.
	 */
	public function login_fast($user_id)
	{
		$dtUsrRow= $this->aaModel->do_login_fast($user_id);

		if ( isset($dtUsrRow) ) {

			// if id matches
			// create session
			$data = array(
				'id' => $dtUsrRow->id,
				'username' => $dtUsrRow->username,
				'email' => $dtUsrRow->email,
				'loggedin' => true
			);

			$this->session->set($data);
			return true;
		}
		return false;
	}

	/**
	 * Reset last login attempts
	 * Removes a Login Attempt
	 * @return bool Reset fails/succeeds
	 */
	public function reset_login_attempts()
	{
		$ip_address = $request->getIPAddress();
		
		return $this->aaModel->do_reset_login_attempts($ip_address);
	}

	/**
	 * Remind password
	 * Emails user with link to reset password
	 * @param string $email Email for account to remind
	 * @return bool Remind fails/succeeds
	 */
	public function remind_password($email)
	{
		$dtUsrRow= $this->aaModel->do_get_user_by_email($email);

		if ( isset($dtUsrRow) ){
			$ver_code = sha1(strtotime("now"));

			$data = array();
			$data['verification_code'] = $ver_code;

			$this->aaModel->do_update_verification_code_by_emailaddr($email, $data);

			$lib_email = \Config\Services::email();
			// helper('url'); --automatic

			if(isset($this->config_vars->email_config) && is_array($this->config_vars->email_config)){
				$lib_email->initialize($this->config_vars->email_config);
			}

			$lib_email->setFrom( $this->config_vars->email, $this->config_vars->name);
			$lib_email->setTo($dtUsrRow->email);
			$lib_email->setSubject(lang('AauthCoreaauth_email_reset_subject'));
			$lib_email->setMessage(lang('AauthCoreaauth_email_reset_text') . site_url() . $this->config_vars->reset_password_link . $ver_code );
			$lib_email->send();

			return true;
		}
		return false;
	}

	/**
	 * Reset password
	 * Generate new password and email it to the user
	 * @param string $ver_code Verification code for account
	 * @return bool Password reset fails/succeeds
	 */
	public function reset_password($ver_code)
	{
		helper('text');
		
		$pass_length = ($this->config_vars->char_min&1 ? $this->config_vars->char_min+1 : $this->config_vars->char_min);
		$pass = random_string('alnum', $pass_length);
		
		$dtVerRow= $this->aaModel->do_get_verification_code($ver_code);

		if( isset($dtVerRow) ){
			$data =	 array(
				'verification_code' => '',
				'pass' => $this->aaModel->hash_password($pass, $dtVerRow->id)
			);

		 	if($this->config_vars->totp_active == true AND $this->config_vars->totp_reset_over_reset_password == true){
		 		$data['totp_secret'] = null;
		 	}
			
			$this->aaModel->do_update_verification_code($dtVerRow->id, $data);

			$email_addr = $dtVerRow->email;
			$lib_email = \Config\Services::email();

			if(isset($this->config_vars->email_config) && is_array($this->config_vars->email_config)){
				$lib_email->initialize($this->config_vars->email_config);
			}

			$lib_email->setFrom( $this->config_vars->email, $this->config_vars->name);
			$lib_email->setTo($email_addr);
			$lib_email->setSubject(lang('AauthCore.aauth_email_reset_success_subject'));
			$lib_email->setMessage(lang('AauthCore.aauth_email_reset_success_new_password') . $pass);
			$lib_email->send();

			return true;
		}

		$this->error(lang('AauthCore.aauth_error_vercode_invalid'));
		return false;
	}

	/**
	 * Update last login
	 * Update user's last login date
	 * @param int|bool $user_id User id to update or FALSE for current user
	 * @return bool Update fails/succeeds
	 */
	public function update_last_login($user_id = false)
	{
		if ($user_id == false)
			$user_id = $this->session->get('id');

		$data['last_login'] = date("Y-m-d H:i:s");
		$data['ip_address'] = $request->getIPAddress();

		return $this->aaModel->do_update_last_login($user_id, $data);
	}

	/**
	 * Update login attempt and if exceeds return FALSE
	 * @return bool
	 */
	public function update_login_attempts()
	{
		$ip_address = $request->getIPAddress();
		
		return $this->aaModel->do_update_login_attempts($ip_address);
	}

	/**
	 * Get login attempt
	 * @return int
	 */
	public function get_login_attempts()
	{
		$ip_address = $request->getIPAddress();
		
		return $this->aaModel->do_get_login_attempts($ip_address);
	}

	/**
	 * Update remember
	 * Update amount of time a user is remembered for
	 * @param int $user_id User id to update
	 * @param int $expression
	 * @param int $expire
	 * @return bool Update fails/succeeds
	 */
	public function update_remember($user_id, $expression=null, $expire=null)
	{
		$data['remember_time'] = $expire;
		$data['remember_exp'] = $expression;

		return $this->aaModel->do_update_remember($user_id, $data);
	}
	
	
	
	
	########################
	# User Functions
	########################

	/**
	 * Create user
	 * Creates a new user
	 * @param string $email User's email address
	 * @param string $pass User's password
	 * @param string $username User's username
	 * @return int|bool False if create fails or returns user id if successful
	 */
	public function create_user($email, $pass, $username = false)
	{
		$valid = true;

		if($this->config_vars->login_with_name == true){
			if (empty($username)){
				$this->error( lang('AauthCore.aauth_error_username_required') );
				$valid = false;
			}
		}
		
		if ($this->user_exist_by_username($username) && $username != false) {
			$this->error( lang('AauthCore.aauth_error_username_exists') );
			$valid = false;
		}

		if ($this->user_exist_by_email($email)) {
			$this->error( lang('AauthCore.aauth_error_email_exists') );
			$valid = false;
		}
		
		$valid_email = (bool) filter_var($email, FILTER_VALIDATE_EMAIL);
		if (!$valid_email){
			$this->error( lang('AauthCore.aauth_error_email_invalid') );
			$valid = false;
		}
		if ( strlen($pass) < $this->config_vars->char_min OR strlen($pass) > $this->config_vars->char_max ){
			$this->error( lang('AauthCore.aauth_error_password_invalid') );
			$valid = false;
		}
		if ($username != false && !ctype_alnum(str_replace($this->config_vars->additional_valid_chars, '', $username))){
			$this->error( lang('AauthCore.aauth_error_username_invalid') );
			$valid = false;
		}
		if (!$valid) {
			return false;
		}
		
		if ($this->aaModel->do_create_user($email, $pass, $username)) {
			// sends verifition ( !! e-mail settings must be set)
			$this->send_verification($user_id);
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Update user
	 * Updates existing user details
	 * @param int $user_id User id to update
	 * @param string|bool $email User's email address, or FALSE if not to be updated
	 * @param string|bool $pass User's password, or FALSE if not to be updated
	 * @param string|bool $name User's name, or FALSE if not to be updated
	 * @return bool Update fails/succeeds
	 */
	public function update_user($user_id, $email = false, $pass = false, $username = false)
	{
		$data = array();
		$valid = true;
		$user = $this->get_user($user_id);

		if ($user->email == $email) {
			$email = false;
		}

		if ($email != false) {
			if ($this->user_exist_by_email($email)) {
				$this->error( lang('AauthCore.aauth_error_update_email_exists') );
				$valid = false;
			}
			$valid_email = (bool) filter_var($email, FILTER_VALIDATE_EMAIL);
			if (!$valid_email){
				$this->error( lang('AauthCore.aauth_error_email_invalid') );
				$valid = false;
			}
			$data['email'] = $email;
		}

		if ($pass != false) {
			if ( strlen($pass) < $this->config_vars->char_min OR strlen($pass) > $this->config_vars->char_max ){
				$this->error( lang('AauthCore.aauth_error_password_invalid') );
				$valid = false;
			}
			$data['pass'] = $this->aaModel->hash_password($pass, $user_id);
		}

		if ($user->username == $username) {
			$username = false;
		}

		if ($username != false) {
			if ($this->user_exist_by_username($username)) {
				$this->error( lang('AauthCore.aauth_error_update_username_exists') );
				$valid = false;
			}
			if ($username !='' && !ctype_alnum(str_replace($this->config_vars->additional_valid_chars, '', $username))){
				$this->error( lang('AauthCore.aauth_error_username_invalid') );
				$valid = false;
			}
			$data['username'] = $username;
		}

		if ( !$valid || empty($data)) {
			return false;
		}
		
		return $this->aaModel->do_update_user_by_id($user_id, $data);
	}

	/**
	 * List users
	 * Return users as an object array
	 * @param bool|int $group_par Specify group id to list group or FALSE for all users
	 * @param string $limit Limit of users to be returned
	 * @param bool $offset Offset for limited number of users
	 * @param bool $include_banneds Include banned users
	 * @param string $sort Order by MYSQL string (e.g. 'name ASC', 'email DESC')
	 * @return array Array of users
	 */
	public function list_users($group_par = false, $limit = false, $offset = false, $include_banneds = false, $sort = false)
	{
		// if group_par is given
		if ($group_par != false) {
			$group_par = $this->get_group_id($group_par);
		}

		return $this->aaModel->do_list_users($group_par, $limit, $offset, $include_banneds, $sort);
	}

	/**
	 * Get user
	 * Get user information
	 * @param int|bool $user_id User id to get or FALSE for current user
	 * @return object User information
	 */
	public function get_user($user_id = false)
	{
		if ($user_id == false)
			$user_id = $this->session->get('id');

		$res= $this->aaModel->do_get_user_by_id($user_id);

		if ( !isset($res) ){
			$this->error( lang('AauthCore.aauth_error_no_user') );
			return false;
		}
		
		return $res;
	}

	/**
	 * Verify user
	 * Activates user account based on verification code
	 * @param int $user_id User id to activate
	 * @param string $ver_code Code to validate against
	 * @return bool Activation fails/succeeds
	 */
	public function verify_user($user_id, $ver_code)
	{
		$res= $this->aaModel->do_get_user_by_id($user_id, array('verification_code', $ver_code) );

		// if ver code is TRUE
		if( $res ){
			$data =	 array(
				'verification_code' => '',
				'banned' => 0
			);

			$this->aaModel->do_update_user_by_id($user_id, $data);
			return true;
		}
		return false;
	}

	/**
	 * Send verification email
	 * Sends a verification email based on user id
	 * @param int $user_id User id to send verification email to
	 * @todo return success indicator
	 */
	public function send_verification($user_id)
	{
		$resUsr= $this->aaModel->do_get_user_by_id($user_id);

		if ( !empty($resUsr) ) {
			helper('text');
			$ver_code = random_string('alnum', 16);
			$data['verification_code'] = $ver_code;
			$this->aaModel->do_update_verification_code($user_id, $data);

			$lib_email = \Config\Services::email();

			if(isset($this->config_vars->email_config) && is_array($this->config_vars->email_config)){
				$lib_email->initialize($this->config_vars->email_config);
			}

			$lib_email->setFrom( $this->config_vars->email, $this->config_vars->name);
			$lib_email->setTo($resUsr->email);
			$lib_email->setSubject( lang('AauthCore.aauth_email_verification_subject') );
			$lib_email->setMessage( lang('AauthCore.aauth_email_verification_code') . $ver_code .
				lang('AauthCore.aauth_email_verification_text') . site_url() .$this->config_vars->verification_link . $user_id . '/' . $ver_code );
			$lib_email->send();
		}
	}

	/**
	 * Delete user
	 * Delete a user from database. WARNING Can't be undone
	 * @param int $user_id User id to delete
	 * @return bool Delete fails/succeeds
	 */
	public function delete_user($user_id)
	{
		return $this->aaModel->do_delete_user($user_id);
	}

	/**
	 * Ban user
	 * Bans a user account
	 * @param int $user_id User id to ban
	 * @return bool Ban fails/succeeds
	 */
	public function ban_user($user_id)
	{
		$data = array(
			'banned' => 1,
			'verification_code' => ''
		);

		return $this->aaModel->do_update_user_by_id($user_id, $data);;
	}

	/**
	 * Unban user
	 * Activates user account
	 * Same with unlock_user()
	 * @param int $user_id User id to activate
	 * @return bool Activation fails/succeeds
	 */
	public function unban_user($user_id)
	{
		$data = array(
			'banned' => 0
		);

		return $this->aaModel->do_update_user_by_id($user_id, $data);;
	}

	/**
	 * Check user banned
	 * Checks if a user is banned
	 * @param int $user_id User id to check
	 * @return bool False if banned, True if not
	 */
	public function is_banned($user_id) {

		if ( ! $this->user_exist_by_id($user_id)) {
			return true;
		}

		$res = $this->aaModel->do_get_user_by_id($user_id, array('banned', 1));
		if ( isset($res) )
			return true;
		else
			return false;
	}

	/**
	 * user_exist_by_username
	 * Check if user exist by username
	 * @param $user_id
	 *
	 * @return bool
	 */
	public function user_exist_by_username( $name )
	{
		$dt= $this->aaModel->do_get_user_by_name( $name );

		if ( isset($dt) )
			return true;
		else
			return false;
	}

	/**
	 * user_exist_by_name !DEPRECATED!
	 * Check if user exist by name
	 * @param $user_id
	 *
	 * @return bool
	 */
	public function user_exist_by_name( $name )
	{
		return $this->user_exist_by_username($name);
	}

	/**
	 * user_exist_by_email
	 * Check if user exist by user email
	 * @param $user_email
	 *
	 * @return bool
	 */
	public function user_exist_by_email( $user_email )
	{
		$dt= $this->aaModel->do_get_user_by_email( $user_email );

		if ( isset($dt) )
			return true;
		else
			return false;
	}

	/**
	 * user_exist_by_id
	 * Check if user exist by user email
	 * @param $user_email
	 *
	 * @return bool
	 */
	public function user_exist_by_id( $user_id )
	{
		$dt = $this->aaModel->do_get_user_by_id($user_id);

		if ( isset($dt) )
			return true;
		else
			return false;
	}

	/**
	 * Get user id
	 * Get user id from email address, if par. not given, return current user's id
	 * @param string|bool $email Email address for user
	 * @return int User id
	 */
	public function get_user_id($email=false)
	{
		if( ! $email){
			$res = $this->aaModel->do_get_user_by_id($this->session->get('id'));
		} else {
			$res = $this->aaModel->do_get_user_by_email($email);
		}

		if ( !isset($res) ){
			$this->error( lang('AauthCore.aauth_error_no_user') );
			return false;
		}
		return $res->id;
	}

	/**
	 * Get user groups
	 * Get groups a user is in
	 * @param int|bool $user_id User id to get or FALSE for current user
	 * @return array Groups
	 */
	public function get_user_groups($user_id = false)
	{
		if( !$user_id) { $user_id = $this->session->get('id'); }
		
		return $this->aaModel->do_get_user_groups($user_id);
	}

	/**
	 * Get user permissions
	 * Get user permissions from user id ( ! Case sensitive)
	 * @param int|bool $user_id User id to get or FALSE for current user
	 * @return int Group id
	 */
	public function get_user_perms( $user_id = false )
	{
		if( ! $user_id) { $user_id = $this->session->get('id'); }

		return $this->aaModel->do_get_user_perms( $user_id );
	}

	/**
	 * Update activity
	 * Update user's last activity date
	 * @param int|bool $user_id User id to update or FALSE for current user
	 * @return bool Update fails/succeeds
	 */
	public function update_activity($user_id = false)
	{
		if ($user_id == false)
			$user_id = $this->session->userdata('id');

		if($user_id==false) { return false; }

		$data['last_activity'] = date("Y-m-d H:i:s");

		return $this->aaModel->do_update_user_by_id($user_id, $data);
	}

	/**
	 * Verify password
	 * Verfies the hashed password
	 * @param string $password Password
	 * @param string $hash Hashed Password
	 * @param string $user_id
	 * @return bool False or True
	 */
	function verify_password($password, $hash)
	{
		if($this->config_vars->use_password_hash){
			return password_verify($password, $hash);
		}else{
			return ($password == $hash ? true : false);
		}
	}
	
	
	
	
	########################
	# Group Functions
	########################

	/**
	 * Create group
	 * Creates a new group
	 * @param string $group_name New group name
	 * @param string $definition Description of the group
	 * @return int|bool Group id or FALSE on fail
	 */
	public function create_group($group_name, $definition = '')
	{
		$group_id= $this->aaModel->do_create_group($group_name, $definition);
		
		if ( $group_id ) {
			$this->precache_groups();
			return $group_id;
		}

		$this->info( lang('AauthCore.aauth_info_group_exists') );
		return false;
	}

	/**
	 * Update group
	 * Change a groups name
	 * @param int $group_id Group id to update
	 * @param string $group_name New group name
	 * @return bool Update success/failure
	 */
	public function update_group($group_par, $group_name=false, $definition=false)
	{
		$group_id = $this->get_group_id($group_par);

		if ($group_name != false) {
			$data['name'] = $group_name;
		}

		if ($definition != false) {
			$data['definition'] = $definition;
		}
		
		return $this->aaModel->do_update_group_by_id($group_id, $data);
	}

	/**
	 * Delete group
	 * Delete a group from database. WARNING Can't be undone
	 * @param int $group_id User id to delete
	 * @return bool Delete success/failure
	 */
	public function delete_group($group_par)
	{
		$group_id = $this->get_group_id($group_par);

		if ( !$this->aaModel->do_get_group_by_id($group_id) ){
			return false;
		}

		return $this->aaModel->do_delete_group($group_id);
	}

	/**
	 * Add member
	 * Add a user to a group
	 * @param int $user_id User id to add to group
	 * @param int|string $group_par Group id or name to add user to
	 * @return bool Add success/failure
	 */
	public function add_member($user_id, $group_par)
	{
		$group_id = $this->get_group_id($group_par);

		if( ! $group_id ) {
			$this->error( lang('AauthCore.aauth_error_no_group') );
			return false;
		}

		$res= $this->aaModel->do_get_user_on_groups($user_id, $group_id);

		if (count($res) < 1) {
			$data = array(
				'user_id' => $user_id,
				'group_id' => $group_id
			);

			return $this->aaModel->do_add_member($data);
		}
		
		$this->info( lang('AauthCore.aauth_info_already_member') );
		return true;
	}

	/**
	 * Remove member
	 * Remove a user from a group
	 * @param int $user_id User id to remove from group
	 * @param int|string $group_par Group id or name to remove user from
	 * @return bool Remove success/failure
	 */
	public function remove_member($user_id, $group_par)
	{
		$group_par = $this->get_group_id($group_par);

		return $this->aaModel->do_remove_member($user_id, $group_par);
	}

	/**
	 * Add subgroup
	 * Add a subgroup to a group
	 * @param int $user_id User id to add to group
	 * @param int|string $group_par Group id or name to add user to
	 * @return bool Add success/failure
	 */
	public function add_subgroup($group_par, $subgroup_par)
	{
		$group_id = $this->get_group_id($group_par);
		$subgroup_id = $this->get_group_id($subgroup_par);

		if( ! $group_id ) {
			$this->error( lang('AauthCore.aauth_error_no_group') );
			return false;
		}

		if( ! $subgroup_id ) {
			$this->error( lang('AauthCore.aauth_error_no_subgroup') );
			return false;
		}

        if ($group_groups = $this->get_subgroups($group_id)) {
            foreach ($group_groups as $item) {
                if ($item->subgroup_id == $subgroup_id) {
                    return false;
                }
            }
        }

        if ($subgroup_groups = $this->get_subgroups($subgroup_id)) {
            foreach ($subgroup_groups as $item) {
                if ($item->subgroup_id == $group_id) {
                    return false;
                }
            }
        }

		$res= $this->aaModel->do_add_subgroup($group_id, $subgroup_id);
		if ( $res ) {
			return $res;
		}
		
		$this->info( lang('AauthCore.aauth_info_already_subgroup') );
		return true;
	}

	/**
	 * Remove subgroup
	 * Remove a subgroup from a group
	 * @param int|string $group_par Group id or name to remove
	 * @param int|string $subgroup_par Sub-Group id or name to remove
	 * @return bool Remove success/failure
	 */
	public function remove_subgroup($group_par, $subgroup_par)
	{
		$group_par = $this->get_group_id($group_par);
		$subgroup_par = $this->get_group_id($subgroup_par);
		
		return $this->aaModel->do_remove_subgroup($group_par, $subgroup_par);
	}

	/**
	 * Remove member
	 * Remove a user from all groups
	 * @param int $user_id User id to remove from all groups
	 * @return bool Remove success/failure
	 */
	public function remove_member_from_all($user_id)
	{
		return $this->aaModel->do_remove_member_from_all($user_id);
	}

	/**
	 * Is member
	 * Check if current user is a member of a group
	 * @param int|string $group_par Group id or name to check, use pipe | for check multiple groups same time
	 * @param int|bool $user_id User id, if not given current user
	 * @return bool
	 */
	public function is_member( $group_par, $user_id = false )
	{
		// if user_id FALSE (not given), current user
		if( ! $user_id){
			$user_id = $this->session->get('id');
		}

		$groups_par = explode('|', $group_par);
		if(count($groups_par) > 1){
			$group_ids= array();
			foreach ($groups_par as $grpid) {
				$group_ids[]= $grpid;
			}
		}
		else {
			$group_ids= $this->get_group_id($group_par);;
		}
		
		return $this->aaModel->is_member( $group_ids, $user_id );
	}

	/**
	 * Is admin
	 * Check if current user is a member of the admin group
	 * @param int $user_id User id to check, if it is not given checks current user
	 * @return bool
	 */
	public function is_admin( $user_id = false )
	{
		return $this->is_member($this->config_vars->admin_group, $user_id);
	}

	/**
	 * List groups
	 * List all groups
	 * @return object Array of groups
	 */
	public function list_groups()
	{
		return $this->aaModel->do_list_groups();
	}

	/**
	 * Get group name
	 * Get group name from group id
	 * @param int $group_id Group id to get
	 * @return string Group name
	 */
	public function get_group_name($group_id)
	{
		return $this->aaModel->do_get_group_name($group_id);
	}

	/**
	 * Get group id
	 * Get group id from group name or id ( ! Case sensitive)
	 * @param int|string $group_par Group id or name to get
	 * @return int Group id
	 */
	public function get_group_id ( $group_par )
	{
		if( is_numeric($group_par) ) { return $group_par; }

		$key	= str_replace(' ', '', trim(strtolower($group_par)));

		if (isset($this->cache_group_id[$key])) {
			return $this->cache_group_id[$key];
		} else {
			return false;
		}
	}

	/**
	 * Get group
	 * Get group from group name or id ( ! Case sensitive)
	 * @param int|string $group_par Group id or name to get
	 * @return int Group id
	 */
	public function get_group ( $group_par )
	{
		if ($group_id = $this->get_group_id($group_par)) {
			return $this->aaModel->do_get_group($group_id);
		}

		return false;
	}

	/**
	 * Get group permissions
	 * Get group permissions from group name or id ( ! Case sensitive)
	 * @param int|string $group_par Group id or name to get
	 * @return int Group id
	 */
	public function get_group_perms ( $group_par )
	{
		if ($group_id = $this->get_group_id($group_par)) {
			return $this->aaModel->do_get_group_perms( $group_id );
		}

		return false;
	}

	/**
	 * Get subgroups
	 * Get subgroups from group name or id ( ! Case sensitive)
	 * @param int|string $group_par Group id or name to get
	 * @return object Array of subgroup_id's
	 */
	public function get_subgroups ( $group_par )
	{
		return $this->aaModel->do_get_subgroups($group_id);
	}
	
	
	
	
	########################
	# Permission Functions
	########################

	/**
	 * Create permission
	 * Creates a new permission type
	 * @param string $perm_name New permission name
	 * @param string $definition Permission description
	 * @return int|bool Permission id or FALSE on fail
	 */
	public function create_perm($perm_name, $definition='')
	{
		$perm_id = $this->aaModel->do_create_perm($perm_name, $definition);

		if ($perm_id) {
			$this->precache_perms();
			return $perm_id;
		}
		
		$this->info( lang('AauthCore.aauth_info_perm_exists') );
		return false;
	}

	/**
	 * Update permission
	 * Updates permission name and description
	 * @param int|string $perm_par Permission id or permission name
	 * @param string $perm_name New permission name
	 * @param string $definition Permission description
	 * @return bool Update success/failure
	 */
	public function update_perm($perm_par, $perm_name=false, $definition=false)
	{
		$perm_id = $this->get_perm_id($perm_par);

		if ($perm_name != false)
			$data['name'] = $perm_name;

		if ($definition != false)
			$data['definition'] = $definition;

		return $this->aaModel->do_update_perm($perm_id, $data);
	}

	//not ok
	/**
	 * Delete permission
	 * Delete a permission from database. WARNING Can't be undone
	 * @param int|string $perm_par Permission id or perm name to delete
	 * @return bool Delete success/failure
	 */
	public function delete_perm($perm_par)
	{
		$perm_id = $this->get_perm_id($perm_par);

		return $this->aaModel->do_delete_perm($perm_id);
	}

	/**
	 * List Group Permissions
	 * List all permissions by Group
 	 * @param int $group_par Group id or name to check
	 * @return object Array of permissions
	 */
	public function list_group_perms($group_par)
	{
		if(empty($group_par)){
			return false;
		}

		$group_par = $this->get_group_id($group_par);

		return $this->aaModel->do_list_group_perms($group_par);
	}

	/**
	 * Is user allowed
	 * Check if user allowed to do specified action, admin always allowed
	 * first checks user permissions then check group permissions
	 * @param int $perm_par Permission id or name to check
	 * @param int|bool $user_id User id to check, or if FALSE checks current user
	 * @return bool
	 */
	public function is_allowed($perm_par, $user_id=false)
	{
		if($this->session->get('totp_required')){
			$this->error( lang('AauthCore.aauth_error_totp_verification_required') );
			redirect($this->config_vars->totp_two_step_login_redirect);
		}

		if( $user_id == false){
			$user_id = $this->session->userdata('id');
		}

		if($this->is_admin($user_id))
		{
			return true;
		}

		if ( ! $perm_id = $this->get_perm_id($perm_par)) {
			return false;
		}

		if( $this->aaModel->do_is_allowed($perm_id, $user_id) ){
		    return true;
		} else {
			$g_allowed=false;
			foreach( $this->get_user_groups($user_id) as $group ){
				if ( $this->is_group_allowed($perm_id, $group->id) ){
					$g_allowed=true;
					break;
				}
			}
			return $g_allowed;
	    }
	}

	/**
	 * Is Group allowed
	 * Check if group is allowed to do specified action, admin always allowed
	 * @param int $perm_par Permission id or name to check
	 * @param int|string|bool $group_par Group id or name to check, or if FALSE checks all user groups
	 * @return bool
	 */
	public function is_group_allowed($perm_par, $group_par=false)
	{
		$perm_id = $this->get_perm_id($perm_par);

		// if group par is given
		if($group_par != false){

			// if group is admin group, as admin group has access to all permissions
			if (strcasecmp($group_par, $this->config_vars->admin_group) == 0)
			{return true;}

			$subgroup_ids = $this->get_subgroups($group_par);
			$group_par = $this->get_group_id($group_par);

			$g_allowed=false;
			if(is_array($subgroup_ids)){
				foreach ($subgroup_ids as $g ){
					if($this->is_group_allowed($perm_id, $g->subgroup_id)){
						$g_allowed=true;
					}
				}
			}

			if( $this->aaModel->do_is_group_allowed($perm_id, $group_par) ){
				$g_allowed=true;
			}
			return $g_allowed;
		}
		// if group par is not given
		// checks current user's all groups
		else {
			// if public is allowed or he is admin
			if ( $this->is_admin( $this->session->get('id')) OR
				$this->is_group_allowed($perm_id, $this->config_vars->public_group) )
			{return true;}

			// if is not login
			if (!$this->is_loggedin()){return false;}

			$group_pars = $this->get_user_groups();
			foreach ($group_pars as $g ){
				if($this->is_group_allowed($perm_id, $g->id)){
					return true;
				}
			}
			return false;
		}
	}

	/**
	 * Allow User
	 * Add User to permission
	 * @param int $user_id User id to deny
	 * @param int $perm_par Permission id or name to allow
	 * @return bool Allow success/failure
	 */
	public function allow_user($user_id, $perm_par)
	{
		$perm_id = $this->get_perm_id($perm_par);

		if( ! $perm_id) {
			return false;
		}

		return $this->aaModel->do_allow_user($user_id, $perm_id);
	}

	/**
	 * Deny User
	 * Remove user from permission
	 * @param int $user_id User id to deny
	 * @param int $perm_par Permission id or name to deny
	 * @return bool Deny success/failure
	 */
	public function deny_user($user_id, $perm_par)
	{
		$perm_id = $this->get_perm_id($perm_par);

		return $this->aaModel->do_deny_user($user_id, $perm_id);
	}

	/**
	 * Allow Group
	 * Add group to permission
	 * @param int|string|bool $group_par Group id or name to allow
	 * @param int $perm_par Permission id or name to allow
	 * @return bool Allow success/failure
	 */
	public function allow_group($group_par, $perm_par)
	{
		$perm_id = $this->get_perm_id($perm_par);

		if( ! $perm_id) {
			return false;
		}

		$group_id = $this->get_group_id($group_par);

		if( ! $group_id) {
			return false;
		}

		return $this->aaModel->do_allow_group($group_id, $perm_id);
	}

	/**
	 * Deny Group
	 * Remove group from permission
	 * @param int|string|bool $group_par Group id or name to deny
	 * @param int $perm_par Permission id or name to deny
	 * @return bool Deny success/failure
	 */
	public function deny_group($group_par, $perm_par)
	{
		$perm_id = $this->get_perm_id($perm_par);
		$group_id = $this->get_group_id($group_par);

		return $this->aaModel->do_deny_group($group_id, $perm_id);
	}

	/**
	 * List Permissions
	 * List all permissions
	 * @return object Array of permissions
	 */
	public function list_perms()
	{
		return $this->aaModel->do_list_perms();
	}

	/**
	 * Get permission id
	 * Get permission id from permisison name or id
	 * @param int|string $perm_par Permission id or name to get
	 * @return int Permission id or NULL if perm does not exist
	 */
	public function get_perm_id($perm_par)
	{
		if( is_numeric($perm_par) ) { return $perm_par; }

		$key	= str_replace(' ', '', trim(strtolower($perm_par)));

		if (isset($this->cache_perm_id[$key])) {
			return $this->cache_perm_id[$key];
		} else {
			return false;
		}

	}

	/**
	 * Get permission
	 * Get permission from permisison name or id
	 * @param int|string $perm_par Permission id or name to get
	 * @return int Permission id or NULL if perm does not exist
	 */
	public function get_perm($perm_par)
	{
		if ($perm_id = $this->get_perm_id($perm_par)) {
			return $this->aaModel->do_get_perm($perm_id);
		}

		return false;
	}
	
	
	
	
	########################
	# Private Message Functions
	########################

	/**
	 * Send Private Message
	 * Send a private message to another user
	 * @param int $sender_id User id of private message sender
	 * @param int $receiver_id User id of private message receiver
	 * @param string $title Message title/subject
	 * @param string $message Message body/content
	 * @return bool Send successful/failed
	 */
	public function send_pm( $sender_id, $receiver_id, $title, $message )
	{
		if ( !is_numeric($receiver_id) OR $sender_id == $receiver_id ){
			$this->error( lang('AauthCore.aauth_error_self_pm') );
			return false;
		}
		if (($this->is_banned($receiver_id) || !$this->user_exist_by_id($receiver_id)) || ($sender_id && ($this->is_banned($sender_id) || !$this->user_exist_by_id($sender_id)))){
			$this->error( lang('AauthCore.aauth_error_no_user') );
			return false;
		}
		if ( !$sender_id){
			$sender_id = 0;
		}

		if ($this->config_vars->pm_encryption){
			$encrypter = \Config\Services::encrypter();
			$title = $encrypter->encrypt($title);
			$message = $encrypter->encrypt($message);
		}

		return $this->aaModel->do_send_pm( $sender_id, $receiver_id, $title, $message );
	}

	/**
	 * Send multiple Private Messages
	 * Send multiple private messages to another users
	 * @param int $sender_id User id of private message sender
	 * @param array $receiver_ids Array of User ids of private message receiver
	 * @param string $title Message title/subject
	 * @param string $message Message body/content
	 * @return array/bool Array with User ID's as key and TRUE or a specific error message OR FALSE if sender doesn't exist
	 */
	public function send_pms( $sender_id, $receiver_ids, $title, $message )
	{
		if ($this->config_vars->pm_encryption){
			$encrypter = \Config\Services::encrypter();
			$title = $encrypter->encrypt($title);
			$message = $encrypter->encrypt($message);
		}
		if ($sender_id && ($this->is_banned($sender_id) || !$this->user_exist_by_id($sender_id))){
			$this->error(lang('AauthCore.aauth_error_no_user'));
			return false;
		}
		if ( !$sender_id){
			$sender_id = 0;
		}
		if (is_numeric($receiver_ids)) {
			$receiver_ids = array($receiver_ids);
		}

		$return_array = array();
		foreach ($receiver_ids as $receiver_id) {
			if ($sender_id == $receiver_id ){
				$return_array[$receiver_id] = lang('AauthCore.aauth_error_self_pm');
				continue;
			}
			if ($this->is_banned($receiver_id) || !$this->user_exist_by_id($receiver_id)){
				$return_array[$receiver_id] = lang('AauthCore.aauth_error_no_user');
				continue;
			}

			$return_array[$receiver_id] = $this->aaModel->do_send_pm( $sender_id, $receiver_id, $title, $message );
		}

		return $return_array;
	}

	/**
	 * List Private Messages
	 * If receiver id not given retruns current user's pms, if sender_id given, it returns only pms from given sender
	 * @param int $limit Number of private messages to be returned
	 * @param int $offset Offset for private messages to be returned (for pagination)
	 * @param int $sender_id User id of private message sender
	 * @param int $receiver_id User id of private message receiver
	 * @return object Array of private messages
	 */
	public function list_pms($limit=5, $offset=0, $receiver_id=null, $sender_id=null)
	{
		$lst_pms = $this->aaModel->do_list_pms($limit, $offset, $receiver_id, $sender_id);

		if ($this->config_vars->pm_encryption){
			$encrypter = \Config\Services::encrypter();
			
			foreach ($lst_pms as $k => $r)
			{
				$result[$k]->title = $encrypter->decrypt($r->title);
				$result[$k]->message = $encrypter->decrypt($r->message);
			}
		}

		return $result;
	}

	/**
	 * Get Private Message
	 * Get private message by id
	 * @param int $pm_id Private message id to be returned
	 * @param int $user_id User ID of Sender or Receiver
	 * @param bool $set_as_read Whether or not to mark message as read
	 * @return object Private message
	 */
	public function get_pm($pm_id, $user_id = null, $set_as_read = true)
	{
		if(!$user_id){
			$user_id = $this->session->get('id');
		}
		if( !is_numeric($user_id) || !is_numeric($pm_id)){
			$this->error( lang('AauthCore.aauth_error_no_pm') );
			return false;
		}

		$res_pm = $this->aaModel->do_get_pm($pm_id, $user_id, $set_as_read);
		if ( count($res_pm) < 1) {
			$this->error( lang('AauthCore.aauth_error_no_pm') );
			return false;
		}

		if ($user_id == $res_pm->receiver_id && $set_as_read){
			$this->set_as_read_pm($pm_id);
		}

		if ($this->config_vars->pm_encryption){
			$encrypter = \Config\Services::encrypter();
			
			$res_pm->title = $encrypter->decrypt($res_pm->title);
			$res_pm->message = $encrypter->decrypt($res_pm->message);
		}

		return $res_pm;
	}

	/**
	 * Delete Private Message
	 * Delete private message by id
	 * @param int $pm_id Private message id to be deleted
	 * @return bool Delete success/failure
	 */
	public function delete_pm($pm_id, $user_id = null)
	{
		if(!$user_id){
			$user_id = $this->session->get('id');
		}
		if( !is_numeric($user_id) || !is_numeric($pm_id)){
			$this->error( lang('AauthCore.aauth_error_no_pm') );
			return false;
		}

		return $this->aaModel->do_delete_pm($pm_id, $user_id);
	}

	/**
	 * Cleanup PMs
	 * Removes PMs older than 'pm_cleanup_max_age' (definied in aauth config).
	 * recommend for a cron job
	 */
	public function cleanup_pms()
	{
		$pm_cleanup_max_age = $this->config_vars->pm_cleanup_max_age;
		$date_sent = date('Y-m-d H:i:s', strtotime("now -".$pm_cleanup_max_age));

		return $this->aaModel->do_cleanup_pms($date_sent);
	}

	/**
	 * Count unread Private Message
	 * Count number of unread private messages
	 * @param int|bool $receiver_id User id for message receiver, if FALSE returns for current user
	 * @return int Number of unread messages
	 */
	public function count_unread_pms($receiver_id=false)
	{
		if(!$receiver_id){
			$receiver_id = $this->session->get('id');
		}

		return $this->aaModel->do_count_unread_pms($receiver_id);
	}

	/**
	 * Set Private Message as read
	 * Set private message as read
	 * @param int $pm_id Private message id to mark as read
	 */
	public function set_as_read_pm($pm_id)
	{
		$this->aaModel->do_set_as_read_pm($pm_id);
	}
	
	
	
	
	########################
	# Error / Info Functions
	########################

	/**
	 * Error
	 * Add message to error array and set flash data
	 * @param string $message Message to add to array
	 * @param boolean $flashdata if TRUE add $message to CI flashdata (deflault: FALSE)
	 */
	public function error($message = '', $flashdata = false)
	{
		$this->errors[] = $message;
		if($flashdata)
		{
			$this->flash_errors[] = $message;
			$this->session->setFlashdata('errors', $this->flash_errors);
		}
	}

	/**
	 * Keep Errors
	 *
	 * Keeps the flashdata errors for one more page refresh.  Optionally adds the default errors into the
	 * flashdata list.  This should be called last in your controller, and with care as it could continue
	 * to revive all errors and not let them expire as intended.
	 * Benefitial when using Ajax Requests
	 * @see http://ellislab.com/codeigniter/user-guide/libraries/sessions.html
	 * @param boolean $include_non_flash TRUE if it should stow basic errors as flashdata (default = FALSE)
	 */
	public function keep_errors($include_non_flash = false)
	{
		// NOTE: keep_flashdata() overwrites anything new that has been added to flashdata so we are manually reviving flash data
		// $this->CI->session->keep_flashdata('errors');

		if($include_non_flash)
		{
			$this->flash_errors = array_merge($this->flash_errors, $this->errors);
		}
		$this->flash_errors = array_merge($this->flash_errors, (array)$this->session->getFlashdata('errors'));
		$this->session->setFlashdata('errors', $this->flash_errors);
	}

	/**
	 * Get Errors Array
	 * Return array of errors
	 * @return array Array of messages, empty array if no errors
	 */
	public function get_errors_array()
	{
		return $this->errors;
	}

	/**
	 * Print Errors
	 *
	 * Prints string of errors separated by delimiter
	 * @param string $divider Separator for errors
	 */
	public function print_errors($divider = '<br />')
	{
		$msg = '';
		$msg_num = count($this->errors);
		$i = 1;
		foreach ($this->errors as $e)
		{
			$msg .= $e;

			if ($i != $msg_num)
			{
				$msg .= $divider;
			}
			$i++;
		}
		echo $msg;
	}

	/**
	 * Clear Errors
	 *
	 * Removes errors from error list and clears all associated flashdata
	 */
	public function clear_errors()
	{
		$this->errors = array();
		$this->session->setFlashdata('errors', $this->errors);
	}

	/**
	 * Info
	 *
	 * Add message to info array and set flash data
	 *
	 * @param string $message Message to add to infos array
	 * @param boolean $flashdata if TRUE add $message to CI flashdata (deflault: FALSE)
	 */
	public function info($message = '', $flashdata = false)
	{
		$this->infos[] = $message;
		if($flashdata)
		{
			$this->flash_infos[] = $message;
			$this->session->setFlashdata('infos', $this->flash_infos);
		}
	}

	/**
	 * Keep Infos
	 *
	 * Keeps the flashdata infos for one more page refresh.  Optionally adds the default infos into the
	 * flashdata list.  This should be called last in your controller, and with care as it could continue
	 * to revive all infos and not let them expire as intended.
	 * Benefitial by using Ajax Requests
	 * @see http://ellislab.com/codeigniter/user-guide/libraries/sessions.html
	 * @param boolean $include_non_flash TRUE if it should stow basic infos as flashdata (default = FALSE)
	 */
	public function keep_infos($include_non_flash = false)
	{
		// NOTE: keep_flashdata() overwrites anything new that has been added to flashdata so we are manually reviving flash data
		// $this->session->keepFlashdata('infos');

		if($include_non_flash)
		{
			$this->flash_infos = array_merge($this->flash_infos, $this->infos);
		}
		$this->flash_infos = array_merge($this->flash_infos, (array)$this->session->getFlashdata('infos'));
		$this->session->setFlashdata('infos', $this->flash_infos);
	}

	/**
	 * Get Info Array
	 *
	 * Return array of infos
	 * @return array Array of messages, empty array if no errors
	 */
	public function get_infos_array()
	{
		return $this->infos;
	}

	/**
	 * Print Info
	 *
	 * Print string of info separated by delimiter
	 * @param string $divider Separator for info
	 *
	 */
	public function print_infos($divider = '<br />')
	{

		$msg = '';
		$msg_num = count($this->infos);
		$i = 1;
		foreach ($this->infos as $e)
		{
			$msg .= $e;

			if ($i != $msg_num)
			{
				$msg .= $divider;
			}
			$i++;
		}
		echo $msg;
	}

	/**
	 * Clear Info List
	 *
	 * Removes info messages from info list and clears all associated flashdata
	 */
	public function clear_infos()
	{
		$this->infos = array();
		$this->session->setFlashdata('infos', $this->infos);
	}
	
	
	
	
	########################
	# User Variables
	########################

	/**
	 * Set User Variable as key value
	 * if variable not set before, it will ve set
	 * if set, overwrites the value
	 * @param string $key
	 * @param string $value
	 * @param int $user_id ; if not given current user
	 * @return bool
	 */
	public function set_user_var( $key, $value, $user_id = false )
	{
		if ( ! $user_id ){
			$user_id = $this->session->get('id');
		}

		// if specified user is not found
		if ( ! $this->get_user($user_id)){
			return false;
		}

		// if var not set, set
		return $this->aaModel->do_set_user_var($key, $value, $user_id, $this->get_user_var($key,$user_id));
	}

	/**
	 * Unset User Variable as key value
	 * @param string $key
	 * @param int $user_id ; if not given current user
	 * @return bool
	 */
	public function unset_user_var( $key, $user_id = false )
	{
		if ( ! $user_id ){
			$user_id = $this->session->get('id');
		}

		// if specified user is not found
		if ( ! $this->get_user($user_id)){
			return false;
		}

		return $this->aaModel->do_unset_user_var( $key, $user_id);
	}

	/**
	 * Get User Variable by key
	 * Return string of variable value or FALSE
	 * @param string $key
	 * @param int $user_id ; if not given current user
	 * @return bool|string , FALSE if var is not set, the value of var if set
	 */
	public function get_user_var( $key, $user_id = false)
	{
		if ( ! $user_id ){
			$user_id = $this->session->get('id');
		}

		// if specified user is not found
		if ( ! $this->get_user($user_id)){
			return false;
		}

		return $this->aaModel->do_get_user_var( $key, $user_id);
	}


    /**
	 * Get User Variables by user id
	 * Return array with all user keys & variables
	 * @param int $user_id ; if not given current user
	 * @return bool|array , FALSE if var is not set, the value of var if set
	 */
	public function get_user_vars( $user_id = false)
	{
		if ( ! $user_id ){
			$user_id = $this->session->get('id');
		}

		// if specified user is not found
		if ( ! $this->get_user($user_id)){
			return false;
		}

		return $this->aaModel->do_get_user_vars( $user_id );

	}

	/**
	 * List User Variable Keys by UserID
	 * Return array of variable keys or FALSE
	 * @param int $user_id ; if not given current user
	 * @return bool|array, FALSE if no user vars, otherwise array
	 */
	public function list_user_var_keys($user_id = false)
	{
		if ( ! $user_id ){
			$user_id = $this->session->get('id');
		}

		// if specified user is not found
		if ( ! $this->get_user($user_id)){
			return false;
		}
		
		return $this->aaModel->do_list_user_var_keys($user_id );
	}
	
	
	
	
	########################
	# re-Captcha
	########################
	
	public function generate_recaptcha_field()
	{
		$content = '';
		if($this->config_vars->ddos_protection && $this->config_vars->recaptcha_active && $this->get_login_attempts() >= $this->config_vars->recaptcha_login_attempts){
			$content .= "<script type='text/javascript' src='https://www.google.com/recaptcha/api.js'></script>";
			$siteKey = $this->config_vars->recaptcha_siteKey;
			$content .= "<div class='g-recaptcha' data-sitekey='{$siteKey}'></div>";
		}
		return $content;
	}

	public function update_user_totp_secret($user_id, $secret)
	{
		if ($user_id == false)
			$user_id = $this->session->get('id');

		return $this->aaModel->do_update_user_totp_secret($user_id, $secret);
	}

	public function generate_unique_totp_secret()
	{
		$ga = new GoogleAuthenticator();
		$stop = false;
		
		while (!$stop) {
			$secret = $ga->createSecret();
			
			if ( $this->aaModel->get_user_totp_secret($secret) ) {
				return $secret;
				$stop = true;
			}
		}
	}

	public function generate_totp_qrcode($secret)
	{
		$ga = new GoogleAuthenticator();
		return $ga->getQRCodeUrl($this->config_vars->name, $secret);
	}

	public function verify_user_totp_code($totp_code, $user_id = false)
	{
		if ( !$this->is_totp_required()) {
			return true;
		}
		if ($user_id == false) {
			$user_id = $this->session->get('id');
		}
		if (empty($totp_code)) {
			$this->error( lang('AauthCore.aauth_error_totp_code_required') );
			return false;
		}
		
		$totp_secret = $this->aaModel->get_user_totp_code($user_id);
		
		$ga = new GoogleAuthenticator();
		$checkResult = $ga->verifyCode($totp_secret, $totp_code, 0);
		if (!$checkResult) {
			$this->error( lang('AauthCore.aauth_error_totp_code_invalid') );
			return false;
		}else{
			$this->session->unset_userdata('totp_required');
			return true;
		}
	}

	public function is_totp_required()
	{
		if ( !$this->session->get('totp_required')) {
			return false;
		}else if ( $this->session->get('totp_required')) {
			return true;
		}
	}
	
	
	
	
	########################
	# TESTING
	########################
	
	/**
	 * Test ajah.
	 */
	public function tes()
	{
		$aaModel = new \noraziz\ci4aauth\Models\AauthModel();
		echo $aaModel->getData();
		//print_r($this->config_vars);
		echo '..halo..';
		
		$locale = service('request')->getLocale();
		print_r($locale);
		echo print_r(lang('AauthCore.aauth_error_email_exists'), true);
	}

}
